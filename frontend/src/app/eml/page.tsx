'use client';

import { useState } from 'react';
import { Mail, Upload, CheckCircle, AlertTriangle, ArrowLeft, FileText } from 'lucide-react';
import { phishGuardApi } from '@/services/api';
import { ToastContainer, useToast } from '@/components/Toast';
import type { AnalisisResponse } from '@/types';
import Link from 'next/link';

export default function EMLPage() {
  const [file, setFile] = useState<File | null>(null);
  const [processing, setProcessing] = useState(false);
  const [resultado, setResultado] = useState<AnalisisResponse | null>(null);
  const [hechos, setHechos] = useState<Record<string, unknown> | null>(null);
  const { toasts, addToast, removeToast } = useToast();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!file) return;

    setProcessing(true);
    try {
      const result = await phishGuardApi.analizarEML(file) as AnalisisResponse;
      setResultado(result);
      setHechos(result.hechos || null);
      addToast(`EML procesado: ${result.clasificacion}`, result.clasificacion === 'Legítimo' ? 'success' : result.clasificacion === 'Malicioso' ? 'error' : 'info');
    } catch (error) {
      addToast('Error al procesar archivo', 'error');
    } finally {
      setProcessing(false);
    }
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center gap-4">
        <Link href="/" className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Subir Archivo EML</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">Analiza un archivo de correo electrónico (.eml)</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-gray-800 p-6 rounded-xl border border-gray-200 dark:border-gray-700">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-xl p-8 text-center hover:border-purple-500 transition-colors">
              <input
                type="file"
                accept=".eml"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                className="hidden"
                id="eml-input"
              />
              <label htmlFor="eml-input" className="cursor-pointer">
                <Mail className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-600 dark:text-gray-400">
                  {file ? file.name : 'Selecciona un archivo .eml'}
                </p>
              </label>
            </div>

            {file && (
              <div className="flex items-center justify-between p-3 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-purple-600" />
                  <span className="text-sm">{file.name}</span>
                </div>
                <button type="button" onClick={() => setFile(null)} className="text-gray-400 hover:text-gray-600">
                  <span className="text-sm">Cambiar</span>
                </button>
              </div>
            )}

            <button
              type="submit"
              disabled={!file || processing}
              className="w-full bg-purple-600 hover:bg-purple-700 text-white font-medium py-2.5 rounded-lg disabled:opacity-50 flex items-center justify-center gap-2"
            >
              <Upload className="w-4 h-4" />
              {processing ? 'Escaneando...' : 'Escanear Correo'}
            </button>
          </form>
        </div>

        <div className="space-y-4">
          {resultado ? (
            <>
              <div className={`p-4 rounded-xl border ${
                resultado.clasificacion === 'Malicioso' ? 'bg-red-50 border-red-300 dark:bg-red-900/20' :
                resultado.clasificacion === 'Sospechoso' ? 'bg-yellow-50 border-yellow-300 dark:bg-yellow-900/20' :
                'bg-green-50 border-green-300 dark:bg-green-900/20'
              }`}>
                <div className="flex items-center gap-2 mb-2">
                  {resultado.clasificacion === 'Malicioso' ? (
                    <AlertTriangle className="w-5 h-5 text-red-600" />
                  ) : resultado.clasificacion === 'Sospechoso' ? (
                    <AlertTriangle className="w-5 h-5 text-yellow-600" />
                  ) : (
                    <CheckCircle className="w-5 h-5 text-green-600" />
                  )}
                  <span className="font-bold">{resultado.clasificacion}</span>
                  <span className="text-sm text-gray-500">({resultado.tipo_amenaza})</span>
                </div>
                <p className="text-3xl font-bold">{resultado.resultados?.score_actual}/100</p>
              </div>

              <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
                <div className="p-4 border-b border-gray-200 dark:border-gray-700">
                  <h3 className="font-semibold">Reglas Activadas</h3>
                </div>
                <div className="p-4 space-y-2">
                  {resultado.resultados?.reglas_disparadas?.length ? (
                    resultado.resultados.reglas_disparadas.map((log: any, idx: number) => (
                      <div key={idx} className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                        <span className="font-mono font-bold">{log.regla}</span>
                        <span className="text-sm text-gray-600 dark:text-gray-400">{log.detalle}</span>
                        <span className="bg-red-100 text-red-800 text-xs font-medium px-2 py-1 rounded">+{log.peso_sumado} pts</span>
                      </div>
                    ))
                  ) : (
                    <p className="text-gray-500 text-center py-2">Sin reglas activadas</p>
                  )}
                </div>
              </div>

              <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
                <div className="p-4 border-b border-gray-200 dark:border-gray-700">
                  <h3 className="font-semibold">Hechos Extraídos</h3>
                </div>
                <div className="p-4 space-y-2 text-sm">
                  {hechos && Object.entries(hechos).filter(([k, v]) => v).map(([k, v]) => (
                    <div key={k} className="flex justify-between">
                      <span className="text-gray-500">{k}:</span>
                      <span className="font-medium truncate max-w-[200px]">{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="bg-white dark:bg-gray-800 p-8 rounded-xl border border-gray-200 dark:border-gray-700 text-center">
              <Mail className="w-12 h-12 text-gray-400 mx-auto mb-3" />
              <p className="text-gray-500 dark:text-gray-400">Sube un archivo .eml para analizarlo</p>
            </div>
          )}
        </div>
      </div>

      <ToastContainer toasts={toasts} removeToast={removeToast} />
    </div>
  );
}