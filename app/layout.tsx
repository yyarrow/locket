import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Locket — 零知识密码管理器",
  description: "使用端到端加密和跨设备密文同步的免费私人密码保险库。",
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
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
