'use client';

import { useState, useEffect } from 'react';
import { History, Download, Search, Filter, ArrowLeft } from 'lucide-react';
import { phishGuardApi } from '@/services/api';
import { ToastContainer, useToast } from '@/components/Toast';
import type { RegistroHistorial } from '@/types';
import Link from 'next/link';

export default function HistorialPage() {
  const [historial, setHistorial] = useState<RegistroHistorial[]>([]);
  const [loading, setLoading] = useState(true);
  const [filtro, setFiltro] = useState('');
  const [clasificacionFilter, setClasificacionFilter] = useState('todos');
  const { toasts, addToast, removeToast } = useToast();

  useEffect(() => {
    cargarHistorial();
  }, []);

  async function cargarHistorial() {
    try {
      const data = await phishGuardApi.getHistorial(100);
      setHistorial(data);
    } catch (error) {
      addToast('Error al cargar historial', 'error');
    } finally {
      setLoading(false);
    }
  }

  async function descargarReporte(id: number) {
    try {
      const blob = await phishGuardApi.descargarReporte(id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `phishguard_reporte_${id}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
      addToast('Reporte descargado', 'success');
    } catch (error) {
      addToast('Error al descargar', 'error');
    }
  }

  const historialFiltrado = historial.filter(h => {
    const matchSearch = h.remitente.toLowerCase().includes(filtro.toLowerCase()) ||
      h.tipo_amenaza.toLowerCase().includes(filtro.toLowerCase());
    const matchClasif = clasificacionFilter === 'todos' || h.clasificacion === clasificacionFilter;
    return matchSearch && matchClasif;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Link href="/" className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Historial</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">Registro de todos los análisis realizados</p>
        </div>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex flex-col md:flex-row gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Buscar por remitente o amenaza..."
              value={filtro}
              onChange={(e) => setFiltro(e.target.value)}
              className="w-full pl-10 pr-4 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm"
            />
          </div>
          <select
            value={clasificacionFilter}
            onChange={(e) => setClasificacionFilter(e.target.value)}
            className="px-4 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm"
          >
            <option value="todos">Todos</option>
            <option value="Legítimo">Legítimo</option>
            <option value="Sospechoso">Sospechoso</option>
            <option value="Malicioso">Malicioso</option>
          </select>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th className="px-4 py-3 text-left">ID</th>
                <th className="px-4 py-3 text-left">Fecha</th>
                <th className="px-4 py-3 text-left">Remitente</th>
                <th className="px-4 py-3 text-left">Clasificación</th>
                <th className="px-4 py-3 text-left">Tipo</th>
                <th className="px-4 py-3 text-left">Score</th>
                <th className="px-4 py-3 text-left">Reglas</th>
                <th className="px-4 py-3 text-left">PDF</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {loading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i}>
                    <td colSpan={8} className="px-4 py-4">
                      <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded animate-pulse"></div>
                    </td>
                  </tr>
                ))
              ) : historialFiltrado.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-gray-500">No hay registros</td>
                </tr>
              ) : (
                historialFiltrado.map(h => (
                  <tr key={h.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td className="px-4 py-3 font-mono">#{h.id}</td>
                    <td className="px-4 py-3 text-gray-500">{h.created_at?.slice(0, 10)}</td>
                    <td className="px-4 py-3 font-medium">{h.remitente}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        h.clasificacion === 'Malicioso' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300' :
                        h.clasificacion === 'Sospechoso' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' :
                        'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
                      }`}>
                        {h.clasificacion}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-600 dark:text-gray-400">{h.tipo_amenaza}</td>
                    <td className="px-4 py-3 font-bold">
                      <span className={h.score >= 71 ? 'text-red-600' : h.score >= 31 ? 'text-yellow-600' : 'text-green-600'}>
                        {h.score}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {h.reglas_activadas?.split(',').map((r, i) => (
                          <span key={i} className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs font-mono">
                            {r.trim()}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => descargarReporte(h.id)}
                        className="p-1.5 text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded"
                      >
                        <Download className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <ToastContainer toasts={toasts} removeToast={removeToast} />
    </div>
  );
}