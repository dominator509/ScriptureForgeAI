import Link from 'next/link'

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-24 bg-gray-50">
      <div className="z-10 max-w-5xl w-full items-center justify-between font-mono text-sm lg:flex">
        <h1 className="text-4xl font-bold text-indigo-900">ScriptureForge AI</h1>
      </div>

      <div className="mt-16 flex gap-4">
        <Link
          href="/dashboard"
          className="px-6 py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 font-semibold shadow-md"
        >
          Enter Workspace
        </Link>
      </div>
    </main>
  )
}
