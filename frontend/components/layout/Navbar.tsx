"use client";

import { usePathname } from "next/navigation";
import { Menu, Bell } from "lucide-react";
import { cn } from "@/lib/utils";
import { getUser } from "@/lib/auth";

interface NavbarProps {
  onMenuClick: () => void;
}

const pageTitles: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/scans/new": "New Scan",
  "/findings": "Findings",
  "/reports": "Reports",
  "/settings": "Settings",
};

function getPageTitle(pathname: string): string {
  // Exact match first
  if (pageTitles[pathname]) {
    return pageTitles[pathname];
  }

  // Prefix match for nested routes
  const match = Object.entries(pageTitles).find(([route]) =>
    pathname.startsWith(route + "/")
  );
  if (match) {
    return match[1];
  }

  // Fallback: capitalize the last segment
  const segment = pathname.split("/").filter(Boolean).pop();
  if (segment) {
    return segment.charAt(0).toUpperCase() + segment.slice(1);
  }

  return "Dashboard";
}

export default function Navbar({ onMenuClick }: NavbarProps) {
  const pathname = usePathname();
  const title = getPageTitle(pathname);
  const user = getUser();

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center border-b border-gray-200 bg-white px-4 sm:px-6">
      {/* Mobile hamburger */}
      <button
        onClick={onMenuClick}
        className="mr-3 rounded p-2 text-gray-500 hover:bg-gray-100 hover:text-gray-900 lg:hidden"
      >
        <Menu className="h-5 w-5" />
      </button>

      {/* Page title */}
      <h1 className="text-lg font-semibold text-gray-900">{title}</h1>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Right side actions */}
      <div className="flex items-center gap-3">
        {/* Notification bell */}
        <button
          className={cn(
            "relative rounded-lg p-2 text-gray-400 transition-colors",
            "hover:bg-gray-100 hover:text-gray-600"
          )}
        >
          <Bell className="h-5 w-5" />
          {/* Notification dot */}
          <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-red-500" />
        </button>

        {/* User avatar */}
        <div className="flex h-8 w-8 items-center justify-center rounded-full bg-indigo-600 text-sm font-semibold text-white">
          {(user?.username || "U").charAt(0).toUpperCase()}
        </div>
      </div>
    </header>
  );
}
