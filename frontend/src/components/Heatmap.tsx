'use client';

import { useState } from 'react';
import { HelpCircle } from 'lucide-react';
import type { HeatmapData, Regla } from '@/types';

interface HeatmapProps {
  heatmap: HeatmapData | null;
  reglas: Regla[];
  loading?: boolean;
}

const reglaDescripciones: Record<string, string> = {
  H1: 'Inconsistencia entre dominio From y Return-Path',
  H2: 'Fallo en autenticación SPF o DKIM',
  U1: 'URL contiene dirección IP en lugar de dominio',
  U2: 'Discrepancia entre enlace visible y destino real',
  U3: 'Uso de acortadores de URL sospechosos',
  S1: 'Mensaje contiene urgencia o amenaza',
  S2: 'Saludos genéricos sin personalización',
  A1: 'Archivo adjunto con extensión peligrosa (.exe, .bat)',
  A2: 'Archivo adjunto comprimido (.zip, .rar)',
};

function getHeatColor(value: number, max: number): string {
  if (value === 0) return 'bg-gray-50 dark:bg-gray-700';
  const intensity = Math.min(value / max, 1);
  if (intensity < 0.33) return 'bg-green-100 dark:bg-green-900/50';
  if (intensity < 0.66) return 'bg-yellow-200 dark:bg-yellow-800/50';
  return 'bg-red-200 dark:bg-red-900/50';
}

export default function Heatmap({ heatmap, reglas, loading }: HeatmapProps) {
  const [hoveredCell, setHoveredCell] = useState<{ regla: string; desc: string } | null>(null);

  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 animate-pulse">
        <div className="h-6 w-48 bg-gray-200 dark:bg-gray-700 rounded mb-4"></div>
        <div className="grid grid-cols-9 gap-2">
          {Array.from({ length: 27 }).map((_, i) => (
            <div key={i} className="h-10 bg-gray-100 dark:bg-gray-700 rounded"></div>
          ))}
        </div>
      </div>
    );
  }

  if (!heatmap) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Mapa de Calor de Reglas
        </h3>
        <div className="text-gray-500 dark:text-gray-400 text-center py-8">
          No hay datos suficientes para el mapa de calor
        </div>
      </div>
    );
  }

  const reglasList = ["H1", "H2", "U1", "U2", "U3", "S1", "S2", "A1", "A2"];
  const clasificaciones = ["Legítimo", "Sospechoso", "Malicioso"];

  let maxValue = 0;
  Object.values(heatmap).forEach(clasif => {
    Object.values(clasif).forEach(val => {
      if (val > maxValue) maxValue = val;
    });
  });

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 relative">
      <div className="flex items-center gap-2 mb-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Mapa de Calor de Reglas
        </h3>
        <div className="group relative">
          <HelpCircle className="w-4 h-4 text-gray-400 cursor-help" />
          <div className="absolute left-0 top-6 w-64 p-3 bg-gray-900 text-white text-xs rounded-lg opacity-0 group-hover:opacity-100 transition-opacity z-10 pointer-events-none">
            Este mapa muestra con qué frecuencia se activa cada regla según la clasificación del correo.
          </div>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr>
              <th className="text-left py-2 px-1 text-gray-500 dark:text-gray-400 font-medium">Clasificación</th>
              {reglasList.map(regla => (
                <th key={regla} className="py-2 px-1 text-center">
                  <span
                    className="inline-block px-2 py-1 bg-gray-100 dark:bg-gray-700 rounded text-xs font-mono cursor-help"
                    title={reglaDescripciones[regla]}
                  >
                    {regla}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {clasificaciones.map(clasif => (
              <tr key={clasif}>
                <td className="py-2 px-1 font-medium text-gray-700 dark:text-gray-300">{clasif}</td>
                {reglasList.map(regla => {
                  const value = heatmap[clasif]?.[regla] || 0;
                  return (
                    <td key={regla} className="py-1 px-1 text-center">
                      <div
                        className={`w-full h-8 flex items-center justify-center rounded font-semibold text-xs cursor-default transition-colors ${getHeatColor(value, maxValue || 1)}`}
                        onMouseEnter={() => setHoveredCell({ regla, desc: reglaDescripciones[regla] })}
                        onMouseLeave={() => setHoveredCell(null)}
                      >
                        {value > 0 ? value : '-'}
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {hoveredCell && (
        <div className="mt-3 p-2 bg-blue-50 dark:bg-blue-900/30 rounded text-xs text-blue-700 dark:text-blue-300">
          <strong>{hoveredCell.regla}:</strong> {hoveredCell.desc}
        </div>
      )}

      <div className="mt-4 flex items-center gap-4 text-xs text-gray-500 dark:text-gray-400">
        <span>Intensidad:</span>
        <div className="flex items-center gap-1">
          <span className="w-4 h-4 bg-green-100 dark:bg-green-900/50 rounded"></span>
          <span>Baja</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-4 h-4 bg-yellow-200 dark:bg-yellow-800/50 rounded"></span>
          <span>Media</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-4 h-4 bg-red-200 dark:bg-red-900/50 rounded"></span>
          <span>Alta</span>
        </div>
      </div>
    </div>
  );
}