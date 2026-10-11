import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Bankism • AI Banking Firewall & Guardrail Defense',
  description:
    'Zero-trust Blue-Team AI Firewall guarding core banking operations from prompt injections, jailbreaks, and indirect memo attacks.',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#0b061a] text-purple-100 min-h-screen selection:bg-pink-500/30 selection:text-pink-200 antialiased font-sans relative overflow-x-hidden">
        {/* Subtle Ambient Pink & Purple Background Glow Orbs */}
        <div className="fixed top-0 left-1/4 w-[500px] h-[500px] bg-purple-600/15 rounded-full blur-[140px] pointer-events-none -z-10" />
        <div className="fixed top-1/3 right-10 w-[600px] h-[600px] bg-pink-600/15 rounded-full blur-[160px] pointer-events-none -z-10" />
        <div className="fixed bottom-0 left-10 w-[450px] h-[450px] bg-violet-600/15 rounded-full blur-[140px] pointer-events-none -z-10" />
        {children}
      </body>
    </html>
  );
}
