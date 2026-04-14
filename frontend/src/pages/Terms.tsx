import { Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'

export default function Terms() {
  return (
    <div className="p-8 md:p-12 max-w-4xl mx-auto text-[#e6e6e6cc] font-light">
      <Link to="/" className="inline-flex items-center gap-2 text-sm text-[#e6e6e660] hover:text-white transition mb-8">
        <ArrowLeft size={16} /> Back to Home
      </Link>
      
      <h1 className="text-4xl md:text-5xl font-bold text-white mb-4 tracking-tight" style={{ fontFamily: 'Cormorant, serif' }}>
        Terms & Conditions
      </h1>
      <p className="text-sm text-[#e6e6e680] mb-12 font-mono uppercase tracking-widest">
        Last Updated: April 14, 2026
      </p>

      <div className="space-y-8 leading-relaxed text-[0.95rem]">
        <section>
          <h2 className="text-xl text-white font-medium mb-4">1. Agreement to Terms</h2>
          <p>
            By accessing or using ShieldScan ("the Platform"), you agree to be bound by these Terms and Conditions. If you disagree with any part of the terms, you do not have permission to access the service.
          </p>
        </section>

        <section>
          <h2 className="text-xl text-white font-medium mb-4">2. Intellectual Property & Code Privacy</h2>
          <p className="mb-4">
            We acknowledge and agree that your highly sensitive intellectual property, including all source code, architecture, and proprietary algorithms you choose to scan, remains entirely yours.
          </p>
          <ul className="list-disc pl-5 space-y-2 text-[#e6e6e690]">
            <li>ShieldScan claims <strong>no ownership</strong> rights over the code you scan.</li>
            <li>ShieldScan will <strong>never</strong> utilize, distribute, or copy your code for any purpose outside of generating the requested immediate diagnostic report.</li>
            <li>We do not, under any circumstances, use your private code or architectures to train, fine-tune, or otherwise develop artificial intelligence models.</li>
          </ul>
        </section>

        <section>
          <h2 className="text-xl text-white font-medium mb-4">3. Security and Compliance Assurance</h2>
          <p>
            ShieldScan operates infrastructure heavily inspired by <strong>SOC 2 Type II compliance</strong> controls, meaning we enforce strict policies around Security, Availability, and Confidentiality. You are trusting us with your security posture, and we ensure our environments are logically isolated and ephemerally provisioned per scan.
          </p>
        </section>

        <section>
          <h2 className="text-xl text-white font-medium mb-4">4. User Responsibilities</h2>
          <p>
            You agree to not misuse the ShieldScan platform. Actions strictly prohibited include:
          </p>
          <ul className="list-disc pl-5 space-y-2 text-[#e6e6e690] mt-4">
            <li>Scanning domains or source code repositories you do not legally own or hold authorization to test.</li>
            <li>Attempting to bypass our rate limits or exploit our analysis engines.</li>
            <li>Deploying the platform to facilitate malicious cyber attacks or reconnaissance against unconsenting third parties.</li>
          </ul>
        </section>

        <section>
          <h2 className="text-xl text-white font-medium mb-4">5. Limitation of Liability</h2>
          <p>
            While we utilize industry-leading techniques to identify vulnerabilities, ShieldScan's reports are provided "as is". We do not guarantee the identification of every possible vulnerability or bug. Our output does not act as a legal certification of absolute digital security.
          </p>
        </section>

        <section>
          <h2 className="text-xl text-white font-medium mb-4">6. Modifications</h2>
          <p>
            We reserve the right, at our sole discretion, to modify or replace these Terms at any time. Material changes will be communicated via the platform before they become effective.
          </p>
        </section>

      </div>
    </div>
  )
}
