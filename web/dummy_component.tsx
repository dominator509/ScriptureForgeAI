import React from 'react';
// Simulated Next.js component for heuristics parsing
export const PrimaryButton = ({ onClick, children }) => {
  return (
    <button type="button" onClick={onClick} className="bg-[#1D4ED8] text-white p-2">
      {children}
    </button>
  );
};
