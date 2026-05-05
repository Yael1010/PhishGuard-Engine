'use client';

import { useState, useEffect } from 'react';
import { BarChart3, ArrowLeft, Calendar } from 'lucide-react';
import { phishGuardApi } from '@/services/api';
import { StatsCards } from '@/components/StatsCards';
import BarChart from '@/components/BarChart';
import Heatmap from '@/components/Heatmap';
import { ToastContainer, useToast } from '@/components/Toast';
import type { DatosGraficoDias, HeatmapData, Estadisticas } from '@/types';
import Link from 'next/link';

export default function EstadisticasPage() {
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<Estadisticas | null>(null);
  const [datosGrafico, setDatosGrafico] = useState<DatosGraficoDias | null>(null);
  const [heatmap, setHeatmap] = useState<HeatmapData | null>(null);
  const [dias, setDias] = useState(7);
  const { toasts, addToast, removeToast } = useToast();

  useEffect(() => {
    cargarDatos();
  }, [dias]);

  async function cargarDatos() {
    setLoading(true);
    try {
      const [statsData, graficoData, heatmapData] = await Promise.all([
        phishGuardApi.getEstadisticas(),
        phishGuardApi.getAnalisisDias(dias),
        phishGuardApi.getHeatmapReglas(),
      ]);
      setStats(statsData);
      setDatosGrafico(graficoData);
      setHeatmap(heatmapData);
    } catch (error) {
      addToast('Error al cargar estadísticas', 'error');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/" className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg">
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Estadísticas</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">Análisis y métricas del sistema</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Calendar className="w-4 h-4 text-gray-400" />
          <select
            value={dias}
            onChange={(e) => setDias(Number(e.target.value))}
            className="px-3 py-1.5 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm"
          >
            <option value={7}>Últimos 7 días</option>
            <option value={14}>Últimos 14 días</option>
            <option value={30}>Últimos 30 días</option>
          </select>
        </div>
      </div>

      <StatsCards stats={stats} loading={loading} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <BarChart datos={datosGrafico} loading={loading} />
        <Heatmap heatmap={heatmap} reglas={[]} loading={loading} />
      </div>

      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-white dark:bg-gray-800 p-6 rounded-xl border border-gray-200 dark:border-gray-700">
            <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Distribución de Amenazas</h3>
            <div className="space-y-3">
              {[
                { label: 'Legítimos', value: stats.Legítimo, total: stats.Total, color: 'bg-green-500' },
                { label: 'Sospechosos', value: stats.Sospechoso, total: stats.Total, color: 'bg-yellow-500' },
                { label: 'Maliciosos', value: stats.Malicioso, total: stats.Total, color: 'bg-red-500' },
              ].map(item => (
                <div key={item.label}>
                  <div className="flex justify-between text-sm mb-1">
                    <span>{item.label}</span>
                    <span className="font-medium">{item.value} ({item.total > 0 ? Math.round(item.value / item.total * 100) : 0}%)</span>
                  </div>
                  <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                    <div className={`h-full ${item.color} transition-all`} style={{ width: `${item.total > 0 ? (item.value / item.total) * 100 : 0}%` }}></div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 p-6 rounded-xl border border-gray-200 dark:border-gray-700">
            <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Resumen</h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <p className="text-sm text-gray-500">Total Analizados</p>
                <p className="text-2xl font-bold">{stats.Total}</p>
              </div>
              <div className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <p className="text-sm text-gray-500">Tasa de Detección</p>
                <p className="text-2xl font-bold text-red-600">
                  {stats.Total > 0 ? Math.round((stats.Malicioso + stats.Sospechoso) / stats.Total * 100) : 0}%
                </p>
              </div>
              <div className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <p className="text-sm text-gray-500">Falsos Positivos</p>
                <p className="text-2xl font-bold text-green-600">{stats.Legítimo}</p>
              </div>
              <div className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <p className="text-sm text-gray-500">Amenazas Reales</p>
                <p className="text-2xl font-bold text-red-600">{stats.Malicioso}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      <ToastContainer toasts={toasts} removeToast={removeToast} />
    </div>
  );
}