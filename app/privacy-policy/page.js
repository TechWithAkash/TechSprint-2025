'use client'

import { useState } from 'react'
import Link from 'next/link'
import {
    ArrowLeft,
    Shield,
    Lock,
    Eye,
    Database,
    UserCheck,
    Bell,
    Share2,
    Cookie,
    Mail
} from 'lucide-react'

export default function PrivacyPolicyPage() {
    const [activeSection, setActiveSection] = useState('information')

    const sections = [
        { id: 'information', title: 'Information We Collect', icon: Database },
        { id: 'usage', title: 'How We Use Your Data', icon: Eye },
        { id: 'protection', title: 'Data Protection', icon: Shield },
        { id: 'sharing', title: 'Information Sharing', icon: Share2 },
        { id: 'cookies', title: 'Cookies & Tracking', icon: Cookie },
        { id: 'rights', title: 'Your Rights', icon: UserCheck },
        { id: 'security', title: 'Security Measures', icon: Lock },
        { id: 'notifications', title: 'Communications', icon: Bell },
        { id: 'contact', title: 'Contact Us', icon: Mail }
    ]

    return (
        <div className="min-h-screen bg-gradient-to-br from-emerald-50 via-white to-teal-50">
            {/* Header */}
            <div className="bg-white border-b border-slate-200 sticky top-0 z-10">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
                    <div className="flex items-center justify-between">
                        <Link
                            href="/"
                            className="flex items-center gap-2 text-slate-600 hover:text-slate-900 transition-colors"
                        >
                            <ArrowLeft className="w-5 h-5" />
                            <span className="font-medium">Back</span>
                        </Link>
                        <div className="flex items-center gap-2">
                            <Shield className="w-6 h-6 text-emerald-600" />
                            <h1 className="text-xl font-bold text-slate-800">Privacy Policy</h1>
                        </div>
                    </div>
                </div>
            </div>

            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                <div className="grid lg:grid-cols-4 gap-8">
                    {/* Sidebar Navigation */}
                    <div className="lg:col-span-1">
                        <div className="bg-white rounded-2xl border border-slate-200 p-4 sticky top-24">
                            <h2 className="text-sm font-bold text-slate-800 mb-3 px-2">Contents</h2>
                            <nav className="space-y-1">
                                {sections.map((section) => {
                                    const Icon = section.icon
                                    return (
                                        <button
                                            key={section.id}
                                            onClick={() => setActiveSection(section.id)}
                                            className={`
                        w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-all
                        ${activeSection === section.id
                                                    ? 'bg-emerald-50 text-emerald-700 font-medium'
                                                    : 'text-slate-600 hover:bg-slate-50'
                                                }
                      `}
                                        >
                                            <Icon className="w-4 h-4 flex-shrink-0" />
                                            <span className="text-sm">{section.title}</span>
                                        </button>
                                    )
                                })}
                            </nav>
                        </div>
                    </div>

                    {/* Main Content */}
                    <div className="lg:col-span-3">
                        <div className="bg-white rounded-2xl border border-slate-200 p-6 sm:p-8">
                            {/* Last Updated */}
                            <div className="mb-8 pb-6 border-b border-slate-200">
                                <p className="text-sm text-slate-500">
                                    <span className="font-medium">Last Updated:</span> October 21, 2025
                                </p>
                                <p className="text-sm text-slate-500 mt-1">
                                    <span className="font-medium">Effective Date:</span> October 21, 2025
                                </p>
                            </div>

                            {/* Introduction */}
                            <div className="mb-8">
                                <h2 className="text-2xl font-bold text-slate-800 mb-4">Welcome to WealthWise</h2>
                                <p className="text-slate-600 leading-relaxed">
                                    At WealthWise, we are committed to protecting your privacy and ensuring the security of your personal information.
                                    This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you use our
                                    financial planning application.
                                </p>
                            </div>

                            {/* Section 1: Information We Collect */}
                            <section id="information" className="mb-8 scroll-mt-24">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 bg-emerald-50 rounded-lg flex items-center justify-center">
                                        <Database className="w-5 h-5 text-emerald-600" />
                                    </div>
                                    <h3 className="text-xl font-bold text-slate-800">1. Information We Collect</h3>
                                </div>

                                <div className="space-y-4 text-slate-600">
                                    <div>
                                        <h4 className="font-semibold text-slate-800 mb-2">Personal Information</h4>
                                        <ul className="list-disc list-inside space-y-1 ml-4">
                                            <li>Name and email address</li>
                                            <li>Profile picture (if provided via OAuth)</li>
                                            <li>Authentication credentials</li>
                                            <li>Contact preferences</li>
                                        </ul>
                                    </div>

                                    <div>
                                        <h4 className="font-semibold text-slate-800 mb-2">Financial Information</h4>
                                        <ul className="list-disc list-inside space-y-1 ml-4">
                                            <li>Income and expense records</li>
                                            <li>Budget goals and preferences</li>
                                            <li>Investment information (if provided)</li>
                                            <li>Debt and loan details</li>
                                            <li>Financial goals and targets</li>
                                        </ul>
                                    </div>

                                    <div>
                                        <h4 className="font-semibold text-slate-800 mb-2">Usage Information</h4>
                                        <ul className="list-disc list-inside space-y-1 ml-4">
                                            <li>Device information and browser type</li>
                                            <li>IP address and location data</li>
                                            <li>Usage patterns and preferences</li>
                                            <li>Feature interactions and analytics</li>
                                        </ul>
                                    </div>
                                </div>
                            </section>

                            {/* Section 2: How We Use Your Data */}
                            <section id="usage" className="mb-8 scroll-mt-24">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 bg-blue-50 rounded-lg flex items-center justify-center">
                                        <Eye className="w-5 h-5 text-blue-600" />
                                    </div>
                                    <h3 className="text-xl font-bold text-slate-800">2. How We Use Your Data</h3>
                                </div>

                                <div className="space-y-3 text-slate-600">
                                    <p className="font-medium text-slate-800">We use your information to:</p>
                                    <ul className="list-disc list-inside space-y-2 ml-4">
                                        <li>Provide and maintain our financial planning services</li>
                                        <li>Process your transactions and manage your account</li>
                                        <li>Generate personalized budget recommendations</li>
                                        <li>Send you important updates and notifications</li>
                                        <li>Improve our services and user experience</li>
                                        <li>Analyze usage patterns and optimize performance</li>
                                        <li>Detect and prevent fraud or unauthorized access</li>
                                        <li>Comply with legal obligations and regulations</li>
                                    </ul>
                                </div>
                            </section>

                            {/* Section 3: Data Protection */}
                            <section id="protection" className="mb-8 scroll-mt-24">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 bg-violet-50 rounded-lg flex items-center justify-center">
                                        <Shield className="w-5 h-5 text-violet-600" />
                                    </div>
                                    <h3 className="text-xl font-bold text-slate-800">3. Data Protection</h3>
                                </div>

                                <div className="space-y-3 text-slate-600">
                                    <p>
                                        We implement industry-standard security measures to protect your personal and financial information:
                                    </p>
                                    <ul className="list-disc list-inside space-y-2 ml-4">
                                        <li><strong>Encryption:</strong> All sensitive data is encrypted at rest and in transit using AES-256 encryption</li>
                                        <li><strong>Secure Storage:</strong> Your data is stored in secure, access-controlled databases</li>
                                        <li><strong>Authentication:</strong> Multi-factor authentication options available</li>
                                        <li><strong>Regular Audits:</strong> Periodic security audits and vulnerability assessments</li>
                                        <li><strong>Limited Access:</strong> Strict access controls and employee training</li>
                                    </ul>
                                </div>
                            </section>

                            {/* Section 4: Information Sharing */}
                            <section id="sharing" className="mb-8 scroll-mt-24">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 bg-orange-50 rounded-lg flex items-center justify-center">
                                        <Share2 className="w-5 h-5 text-orange-600" />
                                    </div>
                                    <h3 className="text-xl font-bold text-slate-800">4. Information Sharing</h3>
                                </div>

                                <div className="space-y-3 text-slate-600">
                                    <p className="font-medium text-slate-800">We do NOT sell your personal information. We may share your data only in these circumstances:</p>
                                    <ul className="list-disc list-inside space-y-2 ml-4">
                                        <li><strong>With Your Consent:</strong> When you explicitly authorize sharing</li>
                                        <li><strong>Service Providers:</strong> Trusted third parties who help operate our services (hosting, analytics)</li>
                                        <li><strong>Legal Requirements:</strong> When required by law or to protect our rights</li>
                                        <li><strong>Business Transfers:</strong> In case of merger, acquisition, or asset sale</li>
                                    </ul>
                                    <p className="mt-3 italic">
                                        All third-party service providers are contractually bound to protect your information and use it only for specified purposes.
                                    </p>
                                </div>
                            </section>

                            {/* Section 5: Cookies & Tracking */}
                            <section id="cookies" className="mb-8 scroll-mt-24">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 bg-pink-50 rounded-lg flex items-center justify-center">
                                        <Cookie className="w-5 h-5 text-pink-600" />
                                    </div>
                                    <h3 className="text-xl font-bold text-slate-800">5. Cookies & Tracking</h3>
                                </div>

                                <div className="space-y-3 text-slate-600">
                                    <p>We use cookies and similar tracking technologies to:</p>
                                    <ul className="list-disc list-inside space-y-2 ml-4">
                                        <li>Maintain your login session</li>
                                        <li>Remember your preferences</li>
                                        <li>Analyze usage patterns</li>
                                        <li>Improve site performance</li>
                                    </ul>
                                    <p className="mt-3">
                                        You can control cookie settings through your browser. However, disabling cookies may limit some functionality.
                                    </p>
                                </div>
                            </section>

                            {/* Section 6: Your Rights */}
                            <section id="rights" className="mb-8 scroll-mt-24">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 bg-indigo-50 rounded-lg flex items-center justify-center">
                                        <UserCheck className="w-5 h-5 text-indigo-600" />
                                    </div>
                                    <h3 className="text-xl font-bold text-slate-800">6. Your Rights</h3>
                                </div>

                                <div className="space-y-3 text-slate-600">
                                    <p className="font-medium text-slate-800">You have the right to:</p>
                                    <ul className="list-disc list-inside space-y-2 ml-4">
                                        <li><strong>Access:</strong> Request a copy of your personal data</li>
                                        <li><strong>Correct:</strong> Update or correct inaccurate information</li>
                                        <li><strong>Delete:</strong> Request deletion of your account and data</li>
                                        <li><strong>Export:</strong> Download your data in a portable format</li>
                                        <li><strong>Opt-Out:</strong> Unsubscribe from marketing communications</li>
                                        <li><strong>Restrict:</strong> Limit how we process your information</li>
                                    </ul>
                                    <p className="mt-3">
                                        To exercise these rights, please contact us at{' '}
                                        <a href="mailto:privacy@wealthwise.app" className="text-emerald-600 hover:underline">
                                            privacy@wealthwise.app
                                        </a>
                                    </p>
                                </div>
                            </section>

                            {/* Section 7: Security Measures */}
                            <section id="security" className="mb-8 scroll-mt-24">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 bg-red-50 rounded-lg flex items-center justify-center">
                                        <Lock className="w-5 h-5 text-red-600" />
                                    </div>
                                    <h3 className="text-xl font-bold text-slate-800">7. Security Measures</h3>
                                </div>

                                <div className="space-y-3 text-slate-600">
                                    <p>Our security practices include:</p>
                                    <ul className="list-disc list-inside space-y-2 ml-4">
                                        <li>End-to-end encryption for sensitive financial data</li>
                                        <li>Regular security updates and patches</li>
                                        <li>Secure HTTPS connections</li>
                                        <li>Password hashing using industry standards</li>
                                        <li>Automated backup and recovery systems</li>
                                        <li>24/7 monitoring for suspicious activity</li>
                                    </ul>
                                    <div className="mt-4 p-4 bg-amber-50 border border-amber-200 rounded-lg">
                                        <p className="text-sm text-amber-900">
                                            <strong>⚠️ Important:</strong> While we implement robust security measures, no system is 100% secure.
                                            Please use strong passwords and enable two-factor authentication for additional protection.
                                        </p>
                                    </div>
                                </div>
                            </section>

                            {/* Section 8: Communications */}
                            <section id="notifications" className="mb-8 scroll-mt-24">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 bg-teal-50 rounded-lg flex items-center justify-center">
                                        <Bell className="w-5 h-5 text-teal-600" />
                                    </div>
                                    <h3 className="text-xl font-bold text-slate-800">8. Communications</h3>
                                </div>

                                <div className="space-y-3 text-slate-600">
                                    <p>We may send you:</p>
                                    <ul className="list-disc list-inside space-y-2 ml-4">
                                        <li><strong>Transactional Emails:</strong> Account updates, security alerts, and important notices</li>
                                        <li><strong>Service Updates:</strong> New features, improvements, and maintenance notices</li>
                                        <li><strong>Marketing Communications:</strong> Tips, insights, and promotional offers (opt-in only)</li>
                                    </ul>
                                    <p className="mt-3">
                                        You can manage your communication preferences in your account settings or unsubscribe from marketing emails at any time.
                                    </p>
                                </div>
                            </section>

                            {/* Section 9: Contact Us */}
                            <section id="contact" className="mb-8 scroll-mt-24">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 bg-green-50 rounded-lg flex items-center justify-center">
                                        <Mail className="w-5 h-5 text-green-600" />
                                    </div>
                                    <h3 className="text-xl font-bold text-slate-800">9. Contact Us</h3>
                                </div>

                                <div className="space-y-4 text-slate-600">
                                    <p>If you have questions or concerns about this Privacy Policy or our data practices, please contact us:</p>

                                    <div className="grid sm:grid-cols-2 gap-4">
                                        <div className="p-4 bg-slate-50 rounded-lg">
                                            <p className="font-semibold text-slate-800 mb-2">Email</p>
                                            <a href="mailto:privacy@mywealthwise.tech" className="text-emerald-600 hover:underline">
                                                privacy@mywealthwise.tech
                                            </a>
                                        </div>

                                        <div className="p-4 bg-slate-50 rounded-lg">
                                            <p className="font-semibold text-slate-800 mb-2">Support</p>
                                            <a href="mailto:support@mywealthwise.tech" className="text-emerald-600 hover:underline">
                                                support@mywealthwise.tech
                                            </a>
                                        </div>
                                    </div>

                                    <p className="text-sm">
                                        We will respond to your inquiry within 48 hours.
                                    </p>
                                </div>
                            </section>

                            {/* Changes to Policy */}
                            <div className="mt-8 p-6 bg-blue-50 border border-blue-200 rounded-xl">
                                <h4 className="font-bold text-blue-900 mb-2">Changes to This Policy</h4>
                                <p className="text-sm text-blue-800">
                                    We may update this Privacy Policy from time to time. We will notify you of any changes by posting the new
                                    Privacy Policy on this page and updating the &quot;Last Updated&quot; date. Continued use of our services after
                                    changes constitutes acceptance of the updated policy.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}
