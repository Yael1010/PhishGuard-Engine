'use client';

import { useState, useRef, useEffect } from 'react';
import { HelpCircle } from 'lucide-react';
import type { Regla } from '@/types';

interface ReglaTooltipProps {
  regla: Regla;
  children?: React.ReactNode;
}

const categoriaColores: Record<string, string> = {
  Metadatos: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  Enlaces: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
  Semántica: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
  Adjuntos: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
  OSINT: 'bg-cyan-100 text-cyan-800 dark:bg-cyan-900 dark:text-cyan-200',
};

export default function ReglaTooltip({ regla, children }: ReglaTooltipProps) {
  const [show, setShow] = useState(false);
  const [position, setPosition] = useState<'top' | 'bottom'>('top');
  const tooltipRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (show && tooltipRef.current) {
      const rect = tooltipRef.current.getBoundingClientRect();
      if (rect.top < 100) {
        setPosition('bottom');
      } else {
        setPosition('top');
      }
    }
  }, [show]);

  return (
    <div ref={tooltipRef} className="relative inline-block">
      {children ? (
        <div
          className="cursor-help"
          onMouseEnter={() => setShow(true)}
          onMouseLeave={() => setShow(false)}
        >
          {children}
        </div>
      ) : (
        <button
          type="button"
          onMouseEnter={() => setShow(true)}
          onMouseLeave={() => setShow(false)}
          className="inline-flex items-center justify-center w-5 h-5 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
        >
          <HelpCircle className="w-4 h-4" />
        </button>
      )}

      {show && (
        <div
          className={`
            absolute z-50 w-72 p-4 bg-white dark:bg-gray-800 
            border border-gray-200 dark:border-gray-700 rounded-lg shadow-xl
            transition-all duration-200
            ${position === 'top' ? 'bottom-full mb-2 left-1/2 -translate-x-1/2' : 'top-full mt-2 left-1/2 -translate-x-1/2'}
          `}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="font-mono font-bold text-sm text-gray-900 dark:text-white">
              {regla.id_regla}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded-full ${categoriaColores[regla.categoria] || 'bg-gray-100'}`}>
              {regla.categoria}
            </span>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-300 mb-3">
            {regla.descripcion}
          </p>
          <div className="flex items-center justify-between pt-2 border-t border-gray-100 dark:border-gray-700">
            <span className="text-xs text-gray-500 dark:text-gray-400">Peso asignado</span>
            <span className="text-sm font-bold text-red-600 dark:text-red-400">
              +{regla.peso_asignado} pts
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

export function ReglaBadge({ regla, onClick }: { regla: string; onClick?: () => void }) {
  return (
    <span
      className="inline-flex items-center gap-1 bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 text-[10px] font-mono px-1.5 py-0.5 rounded border border-gray-200 dark:border-gray-600 cursor-help hover:bg-gray-200 dark:hover:bg-gray-600"
      onClick={onClick}
    >
      {regla}
    </span>
  );
}