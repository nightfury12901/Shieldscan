import base64
import httpx
import uuid
from urllib.parse import urlparse

async def generate_github_autofix_pr(repo_url: str, pat: str, file_path: str, new_content: str, title: str, description: str) -> str:
    """
    Creates a new branch on the GitHub repository, updates the specific file,
    and opens a Pull Request with the fix.
    Returns the PR URL.
    """
    if not pat:
        raise ValueError("A GitHub Personal Access Token is required to generate a Pull Request.")

    # Parse owner/repo from URL
    path_parts = urlparse(repo_url).path.strip("/").split("/")
    if len(path_parts) < 2:
        raise ValueError("Invalid GitHub repository URL")
    owner, repo = path_parts[0], path_parts[1]

    headers = {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    async with httpx.AsyncClient(timeout=15) as client:
        # 1. Get default branch (main or master)
        resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers)
        if resp.status_code != 200:
            raise ValueError(f"Could not access repository. Make sure PAT has repo access. {resp.text}")
        default_branch = resp.json().get("default_branch", "main")

        # 2. Get default branch SHA
        resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{default_branch}", headers=headers)
        if resp.status_code != 200:
            raise ValueError("Could not find default branch SHA")
        base_sha = resp.json()["object"]["sha"]

        # 3. Create new branch
        branch_name = f"shieldscan-autofix-{uuid.uuid4().hex[:8]}"
        resp = await client.post(
            f"https://api.github.com/repos/{owner}/{repo}/git/refs",
            headers=headers,
            json={"ref": f"refs/heads/{branch_name}", "sha": base_sha}
        )
        if resp.status_code not in (201, 200):
            raise ValueError(f"Failed to create branch {branch_name}: {resp.text}")

        # 4. Get current file SHA on the new branch
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}?ref={branch_name}",
            headers=headers
        )
        file_sha = None
        if resp.status_code == 200:
            # File exists
            file_data = resp.json()
            if isinstance(file_data, list):
                raise ValueError(f"{file_path} is a directory, not a file.")
            file_sha = file_data["sha"]
        elif resp.status_code != 404:
            raise ValueError(f"Could not fetch original file: {resp.text}")

        # 5. Commit the new file to the branch
        encoded_content = base64.b64encode(new_content.encode("utf-8")).decode("utf-8")
        put_data = {
            "message": f"Security fix by ShieldScan: {title}",
            "content": encoded_content,
            "branch": branch_name
        }
        if file_sha:
            put_data["sha"] = file_sha

        resp = await client.put(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}",
            headers=headers,
            json=put_data
        )
        if resp.status_code not in (200, 201):
            raise ValueError(f"Failed to commit file update: {resp.text}")

        # 6. Open Pull Request
        pr_data = {
            "title": f"🛡️ Security Fix: {title}",
            "body": f"ShieldScan has generated this Auto-Fix to patch a security vulnerability.\n\n### Details\n{description}\n\n*Review this code thoroughly before merging!*",
            "head": branch_name,
            "base": default_branch
        }
        resp = await client.post(
            f"https://api.github.com/repos/{owner}/{repo}/pulls",
            headers=headers,
            json=pr_data
        )
        if resp.status_code != 201:
            raise ValueError(f"Failed to create Pull Request: {resp.text}")

        return resp.json()["html_url"]
