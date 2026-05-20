import React, { useState, useRef, useEffect } from 'react';

export const StudyPlanCreation = () => {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  const generate = () => {
    setLoading(true);
    setResult(null);
    // Simulate generation
    setTimeout(() => {
        setLoading(false);
        setResult("Generation Complete: Week 1 - Ephesians 1");
    }, 2000);
  }

  // Manage focus upon completion
  useEffect(() => {
      if (!loading && result && resultRef.current) {
          resultRef.current.focus();
      }
  }, [loading, result]);

  return (
    <div className="p-4 bg-white text-[#4B5563]">
       <h2>Create Study Plan</h2>
       <label htmlFor="topic-input" className="block text-sm font-medium text-gray-700">Study Topic</label>
       <input id="topic-input" type="text" placeholder="e.g. Grace in Ephesians" className="border border-[#E5E7EB] p-2 text-[#6B7280] w-full" />

       <div aria-live="polite" aria-busy={loading} className="mt-4">
         <button type="button" onClick={generate} disabled={loading} className="bg-[#047857] text-[#FFFFFF] p-2 cursor-pointer w-full disabled:opacity-50">
            {loading ? 'Generating...' : 'Generate Plan'}
         </button>
       </div>

       {result && (
           <div
             ref={resultRef}
             tabIndex={-1}
             className="mt-4 p-4 border border-green-500 bg-green-50 focus:outline-none focus:ring-2 focus:ring-green-600 rounded">
               <h3 className="font-bold text-green-800">Success</h3>
               <p>{result}</p>
           </div>
       )}
    </div>
  );
};
