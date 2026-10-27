"use client";

interface ErrorDisplayProps {
  error: string | null;
  children?: React.ReactNode;
}

export function ErrorDisplay({ error, children }: ErrorDisplayProps) {
  if (error) {
    return (
      <div className="rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
        {error}
      </div>
    );
  }
  return <>{children}</>;
}
