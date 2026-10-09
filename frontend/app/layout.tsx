import type {Metadata} from 'next';
import './style.css';
export const metadata:Metadata={title:'ProofLayer — Agent Execution Firewall',description:'Inspect every tool proposal. Enforce task permissions. Verify execution evidence.'};
export default function RootLayout({children}:{children:React.ReactNode}){return <html lang="en"><body>{children}</body></html>}
