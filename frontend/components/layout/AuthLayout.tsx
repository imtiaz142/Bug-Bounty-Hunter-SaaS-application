"use client";

import { Shield } from "lucide-react";

interface AuthLayoutProps {
  children: React.ReactNode;
}

export default function AuthLayout({ children }: AuthLayoutProps) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-indigo-50 to-white px-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="mb-8 flex flex-col items-center">
          <Shield className="mb-3 h-12 w-12 text-indigo-600" />
          <h1 className="text-2xl font-bold text-gray-900">BugHunter</h1>
        </div>

        {/* Card */}
        <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-lg sm:p-8">
          {children}
        </div>
      </div>
    </div>
  );
}
