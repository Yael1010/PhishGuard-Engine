'use client';

import { useState, useRef } from 'react';
import { FileSpreadsheet, Upload, CheckCircle, AlertTriangle, X, ArrowLeft } from 'lucide-react';
import { phishGuardApi } from '@/services/api';
import { ToastContainer, useToast } from '@/components/Toast';
import Link from 'next/link';

interface ResultadoCSV {
  id: string;
  remitente: string;
  clasificacion: string;
  tipo_amenaza: string;
  score: number;
  reglas: string[];
}

export default function CSVPage() {
  const [file, setFile] = useState<File | null>(null);
  const [processing, setProcessing] = useState(false);
  const [resultados, setResultados] = useState<ResultadoCSV[]>([]);
  const [showResults, setShowResults] = useState(false);
  const { toasts, addToast, removeToast } = useToast();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!file) return;

    setProcessing(true);
    try {
      const result = await phishGuardApi.analizarCSV(file);
      setResultados(result.resultados);
      setShowResults(true);
      addToast(`CSV procesado: ${result.total} correos analizados`, 'success');
    } catch (error) {
      addToast('Error al procesar CSV', 'error');
    } finally {
      setProcessing(false);
    }
  }

  const stats = {
    Legítimo: resultados.filter(r => r.clasificacion === 'Legítimo').length,
    Sospechoso: resultados.filter(r => r.clasificacion === 'Sospechoso').length,
    Malicioso: resultados.filter(r => r.clasificacion === 'Malicioso').length,
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex items-center gap-4">
        <Link href="/" className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Procesar CSV</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">Análisis masivo de correos desde archivo CSV</p>
        </div>
      </div>

      {!showResults ? (
        <div className="bg-white dark:bg-gray-800 p-8 rounded-xl border border-gray-200 dark:border-gray-700">
          <form onSubmit={handleSubmit} className="max-w-xl mx-auto space-y-6">
            <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-xl p-8 text-center hover:border-blue-500 transition-colors">
              <input
                type="file"
                accept=".csv"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                className="hidden"
                id="csv-input"
              />
              <label htmlFor="csv-input" className="cursor-pointer">
                <FileSpreadsheet className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-600 dark:text-gray-400 mb-2">
                  {file ? file.name : 'Haz clic para seleccionar un archivo CSV'}
                </p>
                <p className="text-sm text-gray-500">El archivo debe tener columnas: id, from_domain, return_path, spf, dkim, cuerpo_mensaje, destino_enlace, adjunto</p>
              </label>
            </div>

            {file && (
              <div className="flex items-center justify-between p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                <div className="flex items-center gap-3">
                  <FileSpreadsheet className="w-5 h-5 text-blue-600" />
                  <span className="font-medium">{file.name}</span>
                  <span className="text-sm text-gray-500">({(file.size / 1024).toFixed(1)} KB)</span>
                </div>
                <button type="button" onClick={() => setFile(null)} className="text-gray-400 hover:text-gray-600">
                  <X className="w-5 h-5" />
                </button>
              </div>
            )}

            <button
              type="submit"
              disabled={!file || processing}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 rounded-lg disabled:opacity-50 flex items-center justify-center gap-2"
            >
              <Upload className="w-5 h-5" />
              {processing ? 'Procesando...' : 'Procesar CSV'}
            </button>
          </form>
        </div>
      ) : (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-white dark:bg-gray-800 p-4 rounded-xl border border-gray-200 dark:border-gray-700 border-l-4 border-l-green-500">
              <p className="text-sm text-gray-500">Legítimos</p>
              <p className="text-2xl font-bold text-green-600">{stats.Legítimo}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 p-4 rounded-xl border border-gray-200 dark:border-gray-700 border-l-4 border-l-yellow-400">
              <p className="text-sm text-gray-500">Sospechosos</p>
              <p className="text-2xl font-bold text-yellow-500">{stats.Sospechoso}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 p-4 rounded-xl border border-gray-200 dark:border-gray-700 border-l-4 border-l-red-500">
              <p className="text-sm text-gray-500">Maliciosos</p>
              <p className="text-2xl font-bold text-red-600">{stats.Malicioso}</p>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
              <h2 className="font-semibold text-gray-900 dark:text-white">Resultados ({resultados.length})</h2>
              <button
                onClick={() => { setShowResults(false); setFile(null); setResultados([]); }}
                className="text-sm text-blue-600 hover:underline"
              >
                Procesar otro archivo
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-50 dark:bg-gray-700">
                  <tr>
                    <th className="px-4 py-3 text-left">ID</th>
                    <th className="px-4 py-3 text-left">Remitente</th>
                    <th className="px-4 py-3 text-left">Clasificación</th>
                    <th className="px-4 py-3 text-left">Score</th>
                    <th className="px-4 py-3 text-left">Tipo</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {resultados.map((r, i) => (
                    <tr key={i} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                      <td className="px-4 py-3">{r.id}</td>
                      <td className="px-4 py-3 font-medium">{r.remitente}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium ${
                          r.clasificacion === 'Malicioso' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300' :
                          r.clasificacion === 'Sospechoso' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' :
                          'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
                        }`}>
                          {r.clasificacion === 'Malicioso' ? <AlertTriangle className="w-3 h-3" /> : r.clasificacion === 'Sospechoso' ? <AlertTriangle className="w-3 h-3" /> : <CheckCircle className="w-3 h-3" />}
                          {r.clasificacion}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-bold">{r.score}</td>
                      <td className="px-4 py-3 text-gray-500">{r.tipo_amenaza}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      <ToastContainer toasts={toasts} removeToast={removeToast} />
    </div>
  );
}