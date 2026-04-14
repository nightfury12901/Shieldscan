import { Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'

export default function Privacy() {
  return (
    <div className="p-8 md:p-12 max-w-4xl mx-auto text-[#e6e6e6cc] font-light">
      <Link to="/" className="inline-flex items-center gap-2 text-sm text-[#e6e6e660] hover:text-white transition mb-8">
        <ArrowLeft size={16} /> Back to Home
      </Link>
      
      <h1 className="text-4xl md:text-5xl font-bold text-white mb-4 tracking-tight" style={{ fontFamily: 'Cormorant, serif' }}>
        Privacy Policy
      </h1>
      <p className="text-sm text-[#e6e6e680] mb-12 font-mono uppercase tracking-widest">
        Last Updated: April 14, 2026
      </p>

      <div className="space-y-8 leading-relaxed text-[0.95rem]">
        <section>
          <h2 className="text-xl text-white font-medium mb-4">1. Introduction</h2>
          <p>
            At ShieldScan, we treat your privacy and the security of your proprietary code as our highest priority. 
            This Privacy Policy explains how we collect, use, and protect your information when you use our platform.
          </p>
        </section>

        <section className="bg-[#111] border border-[#ffffff14] p-6 rounded-lg my-8">
          <h2 className="text-lg text-white font-medium mb-3 flex items-center gap-2">
            <span className="text-green-400">●</span> Zero Data Retention & Strict Privacy
          </h2>
          <p className="mb-2">
            <strong>Your code remains yours.</strong> ShieldScan processes your codebase transiently for the sole purpose of generating diagnostic security reports.
          </p>
          <ul className="list-disc pl-5 space-y-2 text-[#e6e6e690] mt-4">
            <li>We <strong>never</strong> store your source code on our servers after an active scan is completed.</li>
            <li>We <strong>never</strong> use your code, proprietary data, or architecture to train our AI models or third-party models.</li>
            <li>All analysis is performed in ephemeral, isolated diagnostic containers that are destroyed immediately after execution.</li>
          </ul>
        </section>

        <section>
          <h2 className="text-xl text-white font-medium mb-4">2. Data We Collect</h2>
          <p className="mb-2">We collect only the minimum required information to provide our services:</p>
          <ul className="list-disc pl-5 space-y-2 text-[#e6e6e690]">
            <li><strong>Account Data:</strong> Email address and authentication credentials via our secure provider (Supabase).</li>
            <li><strong>Metadata:</strong> Number of scans run, module execution times, and platform usage statistics.</li>
            <li><strong>Payment Information:</strong> Handled entirely by our secure payment gateway (Razorpay). We do not store your credit card details.</li>
          </ul>
        </section>

        <section>
          <h2 className="text-xl text-white font-medium mb-4">3. Cloud Security & Compliance</h2>
          <p>
            Our infrastructure is designed around the highest standards of the industry. We enforce rigid access controls and employ military-grade encryption in transit (TLS 1.3) and at rest.
            We are actively pursuing and adhering to <strong>SOC 2 Type II compliance</strong> standards to guarantee the integrity, security, and privacy of the systems processing your data.
          </p>
        </section>

        <section>
          <h2 className="text-xl text-white font-medium mb-4">4. Third-Party Integrations</h2>
          <p>
            When utilizing third-party integrations (e.g., GitHub, GitLab), we require the absolute minimum scopes necessary (such as read-only access). Personal Access Tokens (PATs) provided for private repository scanning are never persisted inside our databases in plain-text.
          </p>
        </section>

        <section>
          <h2 className="text-xl text-white font-medium mb-4">5. Contact Us</h2>
          <p>
            If you have questions about our security practices, compliance posture, or this Privacy Policy, please contact our security team at security@shieldscan.example.com.
          </p>
        </section>
      </div>
    </div>
  )
}
