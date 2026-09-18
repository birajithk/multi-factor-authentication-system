import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Accessway — Accessible authentication",
  description: "Accessible multi-factor authentication with authenticator codes, security keys, and recovery codes.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
