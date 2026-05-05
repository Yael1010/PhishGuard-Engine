'use client';

import { useState, useEffect } from 'react';
import { Shield, BarChart3, FileText, Upload, Mail, Search, Moon, Sun, Download, AlertTriangle, CheckCircle, AlertCircle, History } from 'lucide-react';
import { phishGuardApi } from '@/services/api';
import { StatsCards } from '@/components/StatsCards';
import BarChart from '@/components/BarChart';
import Heatmap from '@/components/Heatmap';
import { ToastContainer, useToast } from '@/components/Toast';
import ReglaTooltip, { ReglaBadge } from '@/components/ReglaTooltip';
import type { Estadisticas, RegistroHistorial, Regla, DatosGraficoDias, HeatmapData, AnalisisResponse } from '@/types';

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState<'lote' | 'manual'>('lote');
  const [darkMode, setDarkMode] = useState(false);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  const [stats, setStats] = useState<Estadisticas | null>(null);
  const [historial, setHistorial] = useState<RegistroHistorial[]>([]);
  const [reglas, setReglas] = useState<Regla[]>([]);
  const [datosGrafico, setDatosGrafico] = useState<DatosGraficoDias | null>(null);
  const [heatmap, setHeatmap] = useState<HeatmapData | null>(null);

  const [resultadoAnalisis, setResultadoAnalisis] = useState<AnalisisResponse | null>(null);
  const [hechosAnalisis, setHechosAnalisis] = useState<Record<string, unknown> | null>(null);

  const { toasts, addToast, removeToast } = useToast();

  const [formData, setFormData] = useState({
    dominio_remitente: 'soporte@miempresa.com',
    dominio_ruta_retorno: 'mailer@servidor-ruso.xyz',
    estado_SPF: 'Aprobado',
    estado_DKIM: 'Aprobado',
    destino_enlace: 'http://192.168.1.50/login',
    cuerpo_mensaje: 'Urgente: Acción requerida en su cuenta.',
    extension_adjunto: '.exe',
  });

  const [csvFile, setCsvFile] = useState<File | null>(null);
  const [emlFile, setEmlFile] = useState<File | null>(null);

  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      setDarkMode(true);
      document.documentElement.classList.add('dark');
    }
  }, []);

  useEffect(() => {
    cargarDatos();
  }, []);

  async function cargarDatos() {
    try {
      const [statsData, historialData, reglasData, graficoData, heatmapData] = await Promise.all([
        phishGuardApi.getEstadisticas(),
        phishGuardApi.getHistorial(100),
        phishGuardApi.getReglas(),
        phishGuardApi.getAnalisisDias(7),
        phishGuardApi.getHeatmapReglas(),
      ]);
      setStats(statsData);
      setHistorial(historialData);
      setReglas(reglasData.reglas);
      setDatosGrafico(graficoData);
      setHeatmap(heatmapData);
    } catch (error) {
      console.error('Error cargando datos:', error);
      addToast('Error al conectar con el servidor', 'error');
    } finally {
      setLoading(false);
    }
  }

  async function handleAnalisisManual(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      const result = await phishGuardApi.analizarManual(formData) as AnalisisResponse;
      setResultadoAnalisis(result);
      setHechosAnalisis(result.hechos || {});
      addToast(`Análisis completado: ${result.clasificacion}`, result.clasificacion === 'Legítimo' ? 'success' : result.clasificacion === 'Malicioso' ? 'error' : 'info');
      cargarDatos();
    } catch (error) {
      addToast('Error al realizar el análisis', 'error');
    } finally {
      setSubmitting(false);
    }
  }

  async function handleCSVUpload(e: React.FormEvent) {
    e.preventDefault();
    if (!csvFile) return;
    setSubmitting(true);
    try {
      const result = await phishGuardApi.analizarCSV(csvFile);
      addToast(`CSV procesado: ${result.total} correos analizados`, 'success');
      cargarDatos();
    } catch (error) {
      addToast('Error al procesar CSV', 'error');
    } finally {
      setSubmitting(false);
      setCsvFile(null);
    }
  }

  async function handleEMLUpload(e: React.FormEvent) {
    e.preventDefault();
    if (!emlFile) return;
    setSubmitting(true);
    try {
      const result = await phishGuardApi.analizarEML(emlFile) as AnalisisResponse;
      setResultadoAnalisis(result);
      setHechosAnalisis(result.hechos || {});
      addToast(`EML procesado: ${result.clasificacion}`, result.clasificacion === 'Legítimo' ? 'success' : result.clasificacion === 'Malicioso' ? 'error' : 'info');
      cargarDatos();
    } catch (error) {
      addToast('Error al procesar EML', 'error');
    } finally {
      setSubmitting(false);
      setEmlFile(null);
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
      addToast('Error al descargar reporte', 'error');
    }
  }

  function toggleDarkMode() {
    setDarkMode(!darkMode);
    if (!darkMode) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('theme', 'light');
    }
  }

  const umbrales = { sospechoso_min: 31, malicioso_min: 71 };

  return (
    <div className="min-h-screen pb-12 transition-colors duration-300">
      <nav className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 fixed w-full z-20 top-0 shadow-sm">
        <div className="max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8 p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="bg-blue-600 text-white p-1.5 rounded-lg">
                <Shield className="w-6 h-6" />
              </div>
              <span className="self-center text-2xl font-bold">PhishGuard</span>
            </div>
            <div className="flex items-center gap-4">
              <span className="bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-300 text-xs font-medium px-2.5 py-1 rounded-full border border-blue-400">
                Motor Heurístico V2.0
              </span>
              <button onClick={toggleDarkMode} className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700">
                {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8 py-8 mt-20">
        <div className="mb-6 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 rounded-t-2xl px-4 pt-4 shadow-sm">
          <ul className="flex flex-wrap -mb-px text-sm font-medium text-center">
            <li className="me-2">
              <button
                onClick={() => setActiveTab('lote')}
                className={`inline-block p-4 border-b-2 rounded-t-lg ${activeTab === 'lote' ? 'border-blue-600 text-blue-600' : 'border-transparent hover:text-gray-600'}`}
              >
                <div className="flex items-center gap-2">
                  <BarChart3 className="w-5 h-5" />
                  Centro de Inteligencia
                </div>
              </button>
            </li>
            <li className="me-2">
              <button
                onClick={() => setActiveTab('manual')}
                className={`inline-block p-4 border-b-2 rounded-t-lg ${activeTab === 'manual' ? 'border-blue-600 text-blue-600' : 'border-transparent hover:text-gray-600'}`}
              >
                <div className="flex items-center gap-2">
                  <Search className="w-5 h-5" />
                  Escáner Individual
                </div>
              </button>
            </li>
          </ul>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-b-2xl rounded-tr-2xl p-6 shadow-sm border border-t-0 border-gray-200 dark:border-gray-700">
          <StatsCards stats={stats} loading={loading} />

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            <BarChart datos={datosGrafico} loading={loading} />
            <Heatmap heatmap={heatmap} reglas={reglas} loading={loading} />
          </div>

          {activeTab === 'lote' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <form onSubmit={handleCSVUpload} className="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
                  <h3 className="font-semibold mb-2 flex items-center gap-2">
                    <Upload className="w-4 h-4" /> Subir CSV
                  </h3>
                  <input
                    type="file"
                    accept=".csv"
                    onChange={(e) => setCsvFile(e.target.files?.[0] || null)}
                    className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 mb-3"
                  />
                  <button type="submit" disabled={!csvFile || submitting} className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg disabled:opacity-50">
                    {submitting ? 'Procesando...' : 'Procesar Lote'}
                  </button>
                </form>

                <form onSubmit={handleEMLUpload} className="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
                  <h3 className="font-semibold mb-2 flex items-center gap-2">
                    <Mail className="w-4 h-4" /> Subir .EML
                  </h3>
                  <input
                    type="file"
                    accept=".eml"
                    onChange={(e) => setEmlFile(e.target.files?.[0] || null)}
                    className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-purple-50 file:text-purple-700 hover:file:bg-purple-100 mb-3"
                  />
                  <button type="submit" disabled={!emlFile || submitting} className="w-full bg-purple-600 hover:bg-purple-700 text-white font-medium py-2 px-4 rounded-lg disabled:opacity-50">
                    {submitting ? 'Escaneando...' : 'Escanear Correo'}
                  </button>
                </form>
              </div>

              <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
                <div className="p-4 border-b border-gray-100 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 flex justify-between items-center">
                  <h3 className="font-bold flex items-center gap-2">
                    <History className="w-5 h-5" /> Registro de Amenazas Global
                  </h3>
                  <span className="bg-blue-100 text-blue-800 text-xs font-medium px-2.5 py-0.5 rounded dark:bg-blue-900 dark:text-blue-300">En la Nube</span>
                </div>
                <div className="overflow-x-auto max-h-[400px]">
                  <table className="w-full text-sm text-left">
                    <thead className="text-xs uppercase bg-gray-100 dark:bg-gray-700 sticky top-0">
                      <tr>
                        <th className="px-4 py-3">ID / Fecha</th>
                        <th className="px-4 py-3">Remitente</th>
                        <th className="px-4 py-3">Categoría</th>
                        <th className="px-4 py-3">Score</th>
                        <th className="px-4 py-3">Reglas</th>
                        <th className="px-4 py-3">Reporte</th>
                      </tr>
                    </thead>
                    <tbody>
                      {historial.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="px-4 py-8 text-center text-gray-500">No hay registros todavía</td>
                        </tr>
                      ) : (
                        historial.map(reg => (
                          <tr key={reg.id} className="border-b dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700">
                            <td className="px-4 py-3">
                              <div className="font-bold">#{reg.id}</div>
                              <div className="text-xs text-gray-500">{reg.created_at?.slice(0, 10)}</div>
                            </td>
                            <td className="px-4 py-3 font-medium">{reg.remitente}</td>
                            <td className="px-4 py-3 font-bold">
                              {reg.tipo_amenaza?.includes('Phishing') ? (
                                <span className="text-red-600">{reg.tipo_amenaza}</span>
                              ) : reg.tipo_amenaza?.includes('Spam') ? (
                                <span className="text-orange-500">{reg.tipo_amenaza}</span>
                              ) : (
                                <span className="text-gray-400">Seguro</span>
                              )}
                            </td>
                            <td className="px-4 py-3 font-bold">
                              <span className={reg.score >= umbrales.malicioso_min ? 'text-red-600' : reg.score >= umbrales.sospechoso_min ? 'text-yellow-600' : 'text-green-600'}>
                                {reg.score}
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex flex-wrap gap-1">
                                {reg.reglas_activadas?.split(',').map((r, i) => (
                                  <ReglaBadge key={i} regla={r.trim()} />
                                ))}
                              </div>
                            </td>
                            <td className="px-4 py-3">
                              <button
                                onClick={() => descargarReporte(reg.id)}
                                className="text-blue-600 hover:text-blue-800"
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
            </div>
          )}

          {activeTab === 'manual' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
              <div className="lg:col-span-5 space-y-6">
                <div className="bg-blue-50 dark:bg-blue-900/30 p-4 rounded-lg border border-blue-200 dark:border-blue-800">
                  <h3 className="font-bold text-blue-800 dark:text-blue-300 text-sm mb-2">Análisis Manual</h3>
                  <p className="text-xs text-gray-600 dark:text-gray-400">Ingresa los datos del correo para analizarlo</p>
                </div>

                <form onSubmit={handleAnalisisManual} className="space-y-4">
                  <div>
                    <label className="block text-xs font-medium mb-1">Remitente (From)</label>
                    <input type="text" value={formData.dominio_remitente} onChange={(e) => setFormData({ ...formData, dominio_remitente: e.target.value })} className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium mb-1">Ruta de Retorno</label>
                    <input type="text" value={formData.dominio_ruta_retorno} onChange={(e) => setFormData({ ...formData, dominio_ruta_retorno: e.target.value })} className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm" />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-medium mb-1">SPF</label>
                      <select value={formData.estado_SPF} onChange={(e) => setFormData({ ...formData, estado_SPF: e.target.value })} className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm">
                        <option>Aprobado</option>
                        <option>Fallo</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-medium mb-1">DKIM</label>
                      <select value={formData.estado_DKIM} onChange={(e) => setFormData({ ...formData, estado_DKIM: e.target.value })} className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm">
                        <option>Aprobado</option>
                        <option>Fallo</option>
                      </select>
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs font-medium mb-1">URL Destino</label>
                    <input type="text" value={formData.destino_enlace} onChange={(e) => setFormData({ ...formData, destino_enlace: e.target.value })} className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium mb-1">Cuerpo del Mensaje</label>
                    <textarea value={formData.cuerpo_mensaje} onChange={(e) => setFormData({ ...formData, cuerpo_mensaje: e.target.value })} rows={2} className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium mb-1">Extensión Adjunto</label>
                    <input type="text" value={formData.extension_adjunto} onChange={(e) => setFormData({ ...formData, extension_adjunto: e.target.value })} className="w-full px-3 py-2 rounded-lg border bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-sm" />
                  </div>
                  <button type="submit" disabled={submitting} className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2.5 rounded-lg disabled:opacity-50">
                    {submitting ? 'Analizando...' : 'Analizar y Guardar'}
                  </button>
                </form>
              </div>

              <div className="lg:col-span-7">
                {resultadoAnalisis ? (
                  <div className="space-y-4">
                    <div className={`p-4 rounded-lg border ${resultadoAnalisis.clasificacion === 'Malicioso' ? 'bg-red-50 border-red-300 text-red-800' : resultadoAnalisis.clasificacion === 'Sospechoso' ? 'bg-yellow-50 border-yellow-300 text-yellow-800' : 'bg-green-50 border-green-300 text-green-800'}`}>
                      <div className="flex items-center gap-2">
                        {resultadoAnalisis.clasificacion === 'Malicioso' ? <AlertCircle className="w-5 h-5" /> : resultadoAnalisis.clasificacion === 'Sospechoso' ? <AlertTriangle className="w-5 h-5" /> : <CheckCircle className="w-5 h-5" />}
                        <span className="font-bold">Resultado: {resultadoAnalisis.clasificacion} ({resultadoAnalisis.tipo_amenaza})</span>
                      </div>
                    </div>

                    <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
                      <div className="bg-gray-800 text-white px-4 py-3 flex justify-between items-center">
                        <span className="font-bold text-sm uppercase">Módulo de Explicación</span>
                        <span className="bg-gray-600 text-xs px-2 py-0.5 rounded font-mono">Score: {resultadoAnalisis.resultados_heuristica?.score_actual}/100</span>
                      </div>
                      <div className="p-4">
                        <h4 className="font-semibold mb-4">Trazabilidad de Inferencia</h4>
                        {resultadoAnalisis.resultados_heuristica?.reglas_disparadas?.length ? (
                          <ol className="relative border-s border-gray-200 dark:border-gray-700 ms-3 space-y-4">
                            {resultadoAnalisis.resultados_heuristica.reglas_disparadas.map((log, idx) => {
                              const reglaInfo = reglas.find(r => r.id_regla === log.regla);
                              return (
                                <li key={idx} className="ms-6 relative">
                                  <span className="absolute -left-3 w-6 h-6 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center">
                                    <span className="text-xs font-bold text-blue-800 dark:text-blue-200">{idx + 1}</span>
                                  </span>
                                  <div className="flex items-center gap-2 mb-1">
                                    <span className="font-mono font-bold">{log.regla}</span>
                                    {reglaInfo && <ReglaTooltip regla={reglaInfo} />}
                                    <span className="bg-red-100 text-red-800 text-xs font-medium px-2 py-0.5 rounded">+{log.peso_sumado} pts</span>
                                  </div>
                                  <p className="text-sm text-gray-600 dark:text-gray-400">{log.detalle}</p>
                                </li>
                              );
                            })}
                          </ol>
                        ) : (
                          <p className="text-gray-500">Sin reglas activadas. El mensaje pasó todos los controles.</p>
                        )}
                      </div>
                    </div>

                    {hechosAnalisis && (
                      <div className="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
                        <h4 className="font-semibold mb-2 text-sm">Hechos Extraídos</h4>
                        <div className="grid grid-cols-2 gap-2 text-xs">
                          {Object.entries(hechosAnalisis).filter(([k, v]) => v).map(([k, v]) => (
                            <div key={k}><span className="font-medium">{k}:</span> {String(v).slice(0, 50)}</div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="flex items-center justify-center h-64 bg-gray-50 dark:bg-gray-700 rounded-xl border-2 border-dashed border-gray-300 dark:border-gray-600">
                    <div className="text-center">
                      <Search className="w-12 h-12 text-gray-400 mx-auto mb-2" />
                      <p className="text-gray-500">Ingresa datos o sube un correo para analizar</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      <ToastContainer toasts={toasts} removeToast={removeToast} />
    </div>
  );
}