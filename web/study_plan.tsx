import React, { useState } from 'react';

export const StudyPlanCreation = () => {
  const [loading, setLoading] = useState(false);

  const generate = () => {
    setLoading(true);
    // Simulate generation
    setTimeout(() => setLoading(false), 2000);
  }

  return (
    <div className="p-4 bg-white text-[#4B5563]">
       <h2>Create Study Plan</h2>
       <input type="text" placeholder="Topic" className="border border-[#E5E7EB] p-2 text-[#9CA3AF]" />
       <div onClick={generate} className="bg-[#10B981] text-[#FFFFFF] mt-4 p-2 cursor-pointer">
          {loading ? 'Generating...' : 'Generate Plan'}
       </div>
    </div>
  );
};
