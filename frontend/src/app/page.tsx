'use client';

import { useState, useEffect } from 'react';
import { Shield, Upload, Mail, FileSpreadsheet, AlertTriangle, CheckCircle, TrendingUp, Activity } from 'lucide-react';
import { phishGuardApi } from '@/services/api';
import { StatsCards } from '@/components/StatsCards';
import BarChart from '@/components/BarChart';
import Heatmap from '@/components/Heatmap';
import { ToastContainer, useToast } from '@/components/Toast';
import type { Estadisticas, RegistroHistorial, Regla, DatosGraficoDias, HeatmapData, AnalisisResponse } from '@/types';
import Link from 'next/link';

export default function DashboardPage() {
  const [loading, setLoading] = useState(true);

  const [stats, setStats] = useState<Estadisticas | null>(null);
  const [historial, setHistorial] = useState<RegistroHistorial[]>([]);
  const [datosGrafico, setDatosGrafico] = useState<DatosGraficoDias | null>(null);
  const [heatmap, setHeatmap] = useState<HeatmapData | null>(null);

  const { toasts, addToast, removeToast } = useToast();

  useEffect(() => {
    cargarDatos();
  }, []);

  async function cargarDatos() {
    try {
      const [statsData, historialData, graficoData, heatmapData] = await Promise.all([
        phishGuardApi.getEstadisticas(),
        phishGuardApi.getHistorial(5),
        phishGuardApi.getAnalisisDias(7),
        phishGuardApi.getHeatmapReglas(),
      ]);
      setStats(statsData);
      setHistorial(historialData);
      setDatosGrafico(graficoData);
      setHeatmap(heatmapData);
    } catch (error) {
      console.error('Error cargando datos:', error);
    } finally {
      setLoading(false);
    }
  }

  const umbrales = { sospechoso_min: 31, malicioso_min: 71 };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">Resumen de actividad de detección de phishing</p>
        </div>
        <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
          <Activity className="w-4 h-4" />
          <span>En vivo</span>
          <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
        </div>
      </div>

      {/* Stats Cards */}
      <StatsCards stats={stats} loading={loading} />

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link
          href="/analisis"
          className="flex items-center gap-4 p-4 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 hover:border-blue-500 dark:hover:border-blue-500 transition-colors group"
        >
          <div className="w-12 h-12 bg-blue-100 dark:bg-blue-900/30 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform">
            <Shield className="w-6 h-6 text-blue-600 dark:text-blue-400" />
          </div>
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-white">Análisis Manual</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400">Analizar un correo específico</p>
          </div>
        </Link>

        <Link
          href="/csv"
          className="flex items-center gap-4 p-4 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 hover:border-green-500 dark:hover:border-green-500 transition-colors group"
        >
          <div className="w-12 h-12 bg-green-100 dark:bg-green-900/30 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform">
            <FileSpreadsheet className="w-6 h-6 text-green-600 dark:text-green-400" />
          </div>
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-white">Procesar CSV</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400">Análisis masivo de correos</p>
          </div>
        </Link>

        <Link
          href="/eml"
          className="flex items-center gap-4 p-4 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 hover:border-purple-500 dark:hover:border-purple-500 transition-colors group"
        >
          <div className="w-12 h-12 bg-purple-100 dark:bg-purple-900/30 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform">
            <Mail className="w-6 h-6 text-purple-600 dark:text-purple-400" />
          </div>
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-white">Subir EML</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400">Analizar archivo de correo</p>
          </div>
        </Link>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <BarChart datos={datosGrafico} loading={loading} />
        <Heatmap heatmap={heatmap} reglas={[]} loading={loading} />
      </div>

      {/* Recent Activity */}
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
          <h2 className="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
            <TrendingUp className="w-5 h-5" />
            Actividad Reciente
          </h2>
          <Link href="/historial" className="text-sm text-blue-600 dark:text-blue-400 hover:underline">
            Ver todo
          </Link>
        </div>
        <div className="divide-y divide-gray-200 dark:divide-gray-700">
          {historial.length === 0 ? (
            <div className="p-8 text-center text-gray-500 dark:text-gray-400">
              No hay actividad reciente
            </div>
          ) : (
            historial.slice(0, 5).map((reg) => (
              <div key={reg.id} className="p-4 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700/50">
                <div className="flex items-center gap-4">
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                    reg.clasificacion === 'Malicioso' ? 'bg-red-100 dark:bg-red-900/30' :
                    reg.clasificacion === 'Sospechoso' ? 'bg-yellow-100 dark:bg-yellow-900/30' :
                    'bg-green-100 dark:bg-green-900/30'
                  }`}>
                    {reg.clasificacion === 'Malicioso' ? (
                      <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400" />
                    ) : reg.clasificacion === 'Sospechoso' ? (
                      <AlertTriangle className="w-5 h-5 text-yellow-600 dark:text-yellow-400" />
                    ) : (
                      <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
                    )}
                  </div>
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">{reg.remitente}</p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">{reg.created_at?.slice(0, 10)}</p>
                  </div>
                </div>
                <div className="text-right">
                  <span className={`inline-block px-3 py-1 rounded-full text-xs font-medium ${
                    reg.clasificacion === 'Malicioso' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300' :
                    reg.clasificacion === 'Sospechoso' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' :
                    'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
                  }`}>
                    {reg.clasificacion}
                  </span>
                  <p className="text-sm font-bold text-gray-700 dark:text-gray-300 mt-1">
                    {reg.score} pts
                  </p>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      <ToastContainer toasts={toasts} removeToast={removeToast} />
    </div>
  );
}