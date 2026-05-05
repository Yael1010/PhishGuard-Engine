import axios from 'axios';
import type {
  Estadisticas,
  RegistroHistorial,
  Regla,
  DatosGraficoDias,
  HeatmapData,
  AnalisisRequest,
  AnalisisResponse
} from '@/types';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const phishGuardApi = {
  async getHealth() {
    const response = await api.get('/api/health');
    return response.data;
  },

  async getReglas() {
    const response = await api.get('/api/reglas');
    return response.data as { reglas: Regla[]; umbrales: { sospechoso_min: number; malicioso_min: number } };
  },

  async getEstadisticas() {
    const response = await api.get('/api/estadisticas');
    return response.data as Estadisticas;
  },

  async getHistorial(limit = 100) {
    const response = await api.get('/api/historial', { params: { limit } });
    return response.data as RegistroHistorial[];
  },

  async getAnalisisDias(dias = 7) {
    const response = await api.get('/api/analisis/dias', { params: { dias } });
    return response.data as DatosGraficoDias;
  },

  async getHeatmapReglas() {
    const response = await api.get('/api/heatmap/reglas');
    return response.data as HeatmapData;
  },

  async analizarCorreo(data: AnalisisRequest) {
    const response = await api.post('/api/v1/analizar', data);
    return response.data as AnalisisResponse;
  },

  async analizarCSV(file: File) {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post('/api/analizar/csv', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  },

  async analizarEML(file: File) {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post('/api/analizar/eml', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  },

  async analizarManual(data: Record<string, string>) {
    const formData = new FormData();
    Object.entries(data).forEach(([key, value]) => {
      formData.append(key, value);
    });
    const response = await api.post('/api/analizar/manual', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data as AnalisisResponse;
  },

  async descargarReporte(analisisId: number) {
    const response = await api.get(`/api/reporte/${analisisId}`, {
      responseType: 'blob',
    });
    return response.data;
  },
};

export default phishGuardApi;