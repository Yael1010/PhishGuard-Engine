export interface Estadisticas {
  Legítimo: number;
  Sospechoso: number;
  Malicioso: number;
  Total: number;
}

export interface RegistroHistorial {
  id: number;
  remitente: string;
  score: number;
  clasificacion: string;
  tipo_amenaza: string;
  reglas_activadas: string;
  created_at: string;
}

export interface ResultadoAnalisis {
  score_actual: number;
  reglas_disparadas: Array<{
    regla: string;
    peso_sumado: number;
    detalle: string;
  }>;
  tipo_amenaza: string;
}

export interface Regla {
  id_regla: string;
  categoria: string;
  peso_asignado: number;
  descripcion: string;
}

export interface DatosGraficoDias {
  dias: string[];
  data: Array<{
    Legítimo: number;
    Sospechoso: number;
    Malicioso: number;
  }>;
}

export interface HeatmapData {
  [clasificacion: string]: {
    [regla: string]: number;
  };
}

export interface AnalisisRequest {
  dominio_remitente: string;
  dominio_ruta_retorno: string;
  estado_SPF?: string;
  estado_DKIM?: string;
  enlaces?: string[];
  texto_enlace?: string;
  cuerpo_mensaje: string;
  extension_adjunto?: string;
}

export interface AnalisisResponse {
  status: string;
  resultados_heuristica?: ResultadoAnalisis;
  clasificacion: string;
  tipo_amenaza: string;
  hechos?: Record<string, unknown>;
}

export interface HechosAnalisis {
  dominio_remitente: string;
  dominio_ruta_retorno: string;
  estado_SPF: string;
  estado_DKIM: string;
  lista_enlaces_URL: string[];
  texto_visible_enlace: string;
  destino_real_enlace: string;
  cuerpo_mensaje: string;
  extension_adjunto: string;
  edad_dominio_dias?: number | null;
}