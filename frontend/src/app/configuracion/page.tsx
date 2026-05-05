'use client';

import { useState, useEffect } from 'react';
import { Settings, ArrowLeft, Save, RotateCcw } from 'lucide-react';
import { phishGuardApi } from '@/services/api';
import { ToastContainer, useToast } from '@/components/Toast';
import type { Regla } from '@/types';
import Link from 'next/link';

export default function ConfiguracionPage() {
  const [reglas, setReglas] = useState<Regla[]>([]);
  const [umbrales, setUmbrales] = useState({ sospechoso_min: 31, malicioso_min: 71 });
  const { toasts, addToast, removeToast } = useToast();

  useEffect(() => {
    phishGuardApi.getReglas().then(data => {
      setReglas(data.reglas);
      setUmbrales(data.umbrales);
    });
  }, []);

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center gap-4">
        <Link href="/" className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Configuración</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">Administra las reglas y umbrales del sistema</p>
        </div>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
            <Settings className="w-5 h-5" />
            Umbrales de Clasificación
          </h2>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Score mínimo para Sospechoso</label>
            <input
              type="number"
              value={umbrales.sospechoso_min}
              onChange={(e) => setUmbrales({ ...umbrales, sospechoso_min: Number(e.target.value) })}
              className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600"
            />
            <p className="text-xs text-gray-500 mt-1">Correos con score mayor o igual a este valor se clasificarán como Sospechosos</p>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Score mínimo para Malicioso</label>
            <input
              type="number"
              value={umbrales.malicioso_min}
              onChange={(e) => setUmbrales({ ...umbrales, malicioso_min: Number(e.target.value) })}
              className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600"
            />
            <p className="text-xs text-gray-500 mt-1">Correos con score mayor o igual a este valor se classificarán como Maliciosos</p>
          </div>
        </div>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="font-semibold text-gray-900 dark:text-white">Reglas Heurísticas</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th className="px-4 py-3 text-left">ID</th>
                <th className="px-4 py-3 text-left">Categoría</th>
                <th className="px-4 py-3 text-left">Descripción</th>
                <th className="px-4 py-3 text-right">Peso</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {reglas.map(regla => (
                <tr key={regla.id_regla} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="px-4 py-3 font-mono font-bold">{regla.id_regla}</td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-1 bg-gray-100 dark:bg-gray-700 rounded text-xs">{regla.categoria}</span>
                  </td>
                  <td className="px-4 py-3 text-gray-600 dark:text-gray-400">{regla.descripcion}</td>
                  <td className="px-4 py-3 text-right font-bold text-red-600">+{regla.peso_asignado}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <ToastContainer toasts={toasts} removeToast={removeToast} />
    </div>
  );
}