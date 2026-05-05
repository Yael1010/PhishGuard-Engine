'use client';

import { useState } from 'react';
import { Shield, Search, AlertTriangle, CheckCircle, AlertCircle, ArrowLeft, Save } from 'lucide-react';
import { phishGuardApi } from '@/services/api';
import { ToastContainer, useToast } from '@/components/Toast';
import ReglaTooltip from '@/components/ReglaTooltip';
import type { AnalisisResponse, Regla } from '@/types';
import Link from 'next/link';

export default function AnalisisPage() {
  const [loading, setLoading] = useState(false);
  const [resultado, setResultado] = useState<AnalisisResponse | null>(null);
  const [reglas, setReglas] = useState<Regla[]>([]);
  const { toasts, addToast, removeToast } = useToast();

  const [formData, setFormData] = useState({
    dominio_remitente: 'soporte@miempresa.com',
    dominio_ruta_retorno: 'mailer@servidor-ruso.xyz',
    estado_SPF: 'Aprobado',
    estado_DKIM: 'Aprobado',
    destino_enlace: 'http://192.168.1.50/login',
    cuerpo_mensaje: 'Urgente: Su cuenta ha sido suspendida. Haga clic aquí para verificar.',
    extension_adjunto: '.exe',
  });

  useState(() => {
    phishGuardApi.getReglas().then(data => setReglas(data.reglas));
  });

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    try {
      const result = await phishGuardApi.analizarManual(formData) as AnalisisResponse;
      setResultado(result);
      addToast(`Análisis completado: ${result.clasificacion}`, result.clasificacion === 'Legítimo' ? 'success' : result.clasificacion === 'Malicioso' ? 'error' : 'info');
    } catch (error) {
      addToast('Error al analizar', 'error');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center gap-4">
        <Link href="/" className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Análisis Manual</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">Ingresa los datos del correo para analizarlo</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <form onSubmit={handleSubmit} className="bg-white dark:bg-gray-800 p-6 rounded-xl border border-gray-200 dark:border-gray-700 space-y-4">
          <h2 className="font-semibold text-gray-900 dark:text-white mb-4">Datos del Correo</h2>
          
          <div>
            <label className="block text-sm font-medium mb-1">Remitente (From)</label>
            <input
              type="text"
              value={formData.dominio_remitente}
              onChange={(e) => setFormData({ ...formData, dominio_remitente: e.target.value })}
              className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Ruta de Retorno (Return-Path)</label>
            <input
              type="text"
              value={formData.dominio_ruta_retorno}
              onChange={(e) => setFormData({ ...formData, dominio_ruta_retorno: e.target.value })}
              className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1">SPF</label>
              <select
                value={formData.estado_SPF}
                onChange={(e) => setFormData({ ...formData, estado_SPF: e.target.value })}
                className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm"
              >
                <option>Aprobado</option>
                <option>Fallo</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">DKIM</label>
              <select
                value={formData.estado_DKIM}
                onChange={(e) => setFormData({ ...formData, estado_DKIM: e.target.value })}
                className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm"
              >
                <option>Aprobado</option>
                <option>Fallo</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">URL Destino</label>
            <input
              type="text"
              value={formData.destino_enlace}
              onChange={(e) => setFormData({ ...formData, destino_enlace: e.target.value })}
              className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Cuerpo del Mensaje</label>
            <textarea
              value={formData.cuerpo_mensaje}
              onChange={(e) => setFormData({ ...formData, cuerpo_mensaje: e.target.value })}
              rows={3}
              className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Extensión de Adjunto</label>
            <input
              type="text"
              value={formData.extension_adjunto}
              onChange={(e) => setFormData({ ...formData, extension_adjunto: e.target.value })}
              className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2.5 rounded-lg disabled:opacity-50 flex items-center justify-center gap-2"
          >
            <Search className="w-4 h-4" />
            {loading ? 'Analizando...' : 'Analizar Correo'}
          </button>
        </form>

        <div className="space-y-4">
          {resultado ? (
            <>
              <div className={`p-4 rounded-xl border ${
                resultado.clasificacion === 'Malicioso' ? 'bg-red-50 border-red-300 dark:bg-red-900/20 dark:border-red-800' :
                resultado.clasificacion === 'Sospechoso' ? 'bg-yellow-50 border-yellow-300 dark:bg-yellow-900/20 dark:border-yellow-800' :
                'bg-green-50 border-green-300 dark:bg-green-900/20 dark:border-green-800'
              }`}>
                <div className="flex items-center gap-3">
                  {resultado.clasificacion === 'Malicioso' ? (
                    <AlertCircle className="w-6 h-6 text-red-600" />
                  ) : resultado.clasificacion === 'Sospechoso' ? (
                    <AlertTriangle className="w-6 h-6 text-yellow-600" />
                  ) : (
                    <CheckCircle className="w-6 h-6 text-green-600" />
                  )}
                  <div>
                    <p className="font-bold text-lg">{resultado.clasificacion}</p>
                    <p className="text-sm opacity-80">{resultado.tipo_amenaza}</p>
                  </div>
                  <div className="ml-auto text-right">
                    <p className="text-2xl font-bold">{resultado.resultados_heuristica?.score_actual}</p>
                    <p className="text-xs opacity-70">/ 100 puntos</p>
                  </div>
                </div>
              </div>

              <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
                <div className="p-4 border-b border-gray-200 dark:border-gray-700">
                  <h3 className="font-semibold text-gray-900 dark:text-white">Reglas Activadas</h3>
                </div>
                <div className="p-4 space-y-3">
                  {resultado.resultados_heuristica?.reglas_disparadas?.length ? (
                    resultado.resultados_heuristica.reglas_disparadas.map((log, idx) => (
                      <div key={idx} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                        <div>
                          <span className="font-mono font-bold text-gray-900 dark:text-white">{log.regla}</span>
                          <p className="text-sm text-gray-600 dark:text-gray-400">{log.detalle}</p>
                        </div>
                        <span className="bg-red-100 text-red-800 text-xs font-medium px-2 py-1 rounded">
                          +{log.peso_sumado} pts
                        </span>
                      </div>
                    ))
                  ) : (
                    <p className="text-gray-500 text-center py-4">No se detectaron anomalías</p>
                  )}
                </div>
              </div>
            </>
          ) : (
            <div className="bg-white dark:bg-gray-800 p-8 rounded-xl border border-gray-200 dark:border-gray-700 text-center">
              <Shield className="w-12 h-12 text-gray-400 mx-auto mb-3" />
              <p className="text-gray-500 dark:text-gray-400">Ingresa los datos y haz clic en analizar</p>
            </div>
          )}
        </div>
      </div>

      <ToastContainer toasts={toasts} removeToast={removeToast} />
    </div>
  );
}