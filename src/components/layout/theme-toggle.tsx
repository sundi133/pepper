"use client";

import { useEffect, useState } from "react";
import { Check, Monitor, Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const id = requestAnimationFrame(() => {
      setMounted(true);
    });
    return () => cancelAnimationFrame(id);
  }, []);

  if (!mounted) {
    return (
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="h-9 w-9 shrink-0"
        disabled
        aria-label="Theme"
      />
    );
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="h-9 w-9 shrink-0 text-muted-foreground hover:text-foreground"
          aria-label="Color theme"
        >
          {theme === "dark" ? (
            <Moon className="h-5 w-5" aria-hidden />
          ) : theme === "light" ? (
            <Sun className="h-5 w-5" aria-hidden />
          ) : (
            <Monitor className="h-5 w-5" aria-hidden />
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-[10rem]">
        <DropdownMenuItem
          className="cursor-pointer"
          onClick={() => setTheme("light")}
        >
          <Sun className="mr-2 h-4 w-4" aria-hidden />
          Light
          {theme === "light" ? (
            <Check className="ml-auto h-4 w-4" aria-hidden />
          ) : null}
        </DropdownMenuItem>
        <DropdownMenuItem
          className="cursor-pointer"
          onClick={() => setTheme("dark")}
        >
          <Moon className="mr-2 h-4 w-4" aria-hidden />
          Dark
          {theme === "dark" ? (
            <Check className="ml-auto h-4 w-4" aria-hidden />
          ) : null}
        </DropdownMenuItem>
        <DropdownMenuItem
          className="cursor-pointer"
          onClick={() => setTheme("system")}
        >
          <Monitor className="mr-2 h-4 w-4" aria-hidden />
          System
          {theme === "system" ? (
            <Check className="ml-auto h-4 w-4" aria-hidden />
          ) : null}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
