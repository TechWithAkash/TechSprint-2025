import { ImageResponse } from 'next/og'

// Image metadata
export const alt = 'WealthWise - Smart Financial Planner'
export const size = {
    width: 1200,
    height: 630,
}

export const contentType = 'image/png'

// Image generation
export default async function Image() {
    return new ImageResponse(
        (
            <div
                style={{
                    fontSize: 128,
                    background: 'linear-gradient(135deg, #059669 0%, #0891b2 100%)',
                    width: '100%',
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: '40px',
                }}
            >
                <div
                    style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        marginBottom: '30px',
                    }}
                >
                    <div
                        style={{
                            width: 120,
                            height: 120,
                            background: 'white',
                            borderRadius: '30px',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            marginRight: '30px',
                        }}
                    >
                        <svg width="80" height="80" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M3 3v18h18" stroke="#059669" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                            <path d="m19 9-5 5-4-4-5 5" stroke="#059669" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                            <path d="M14 9h5v5" stroke="#059669" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                    </div>
                    <div
                        style={{
                            fontSize: 96,
                            fontWeight: 'bold',
                            color: 'white',
                            letterSpacing: '-0.02em',
                        }}
                    >
                        WealthWise
                    </div>
                </div>
                <div
                    style={{
                        fontSize: 36,
                        color: 'rgba(255, 255, 255, 0.95)',
                        textAlign: 'center',
                        maxWidth: '900px',
                        lineHeight: 1.4,
                        fontWeight: 500,
                    }}
                >
                    Smart Financial Planner | Track Expenses, Set Goals & Manage Budget
                </div>
                <div
                    style={{
                        display: 'flex',
                        marginTop: '40px',
                        gap: '30px',
                    }}
                >
                    <div
                        style={{
                            background: 'rgba(255, 255, 255, 0.2)',
                            padding: '15px 30px',
                            borderRadius: '15px',
                            fontSize: 24,
                            color: 'white',
                            fontWeight: 600,
                        }}
                    >
                        🛡️ Bank-Level Security
                    </div>
                    <div
                        style={{
                            background: 'rgba(255, 255, 255, 0.2)',
                            padding: '15px 30px',
                            borderRadius: '15px',
                            fontSize: 24,
                            color: 'white',
                            fontWeight: 600,
                        }}
                    >
                        🤖 AI-Powered Insights
                    </div>
                    <div
                        style={{
                            background: 'rgba(255, 255, 255, 0.2)',
                            padding: '15px 30px',
                            borderRadius: '15px',
                            fontSize: 24,
                            color: 'white',
                            fontWeight: 600,
                        }}
                    >
                        💯 100% Free
                    </div>
                </div>
            </div>
        ),
        {
            ...size,
        }
    )
}
