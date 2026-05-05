'use client';

import { ArrowLeft, HelpCircle, Book, Mail, FileText, Shield } from 'lucide-react';
import Link from 'next/link';

const secciones = [
  {
    titulo: 'Análisis Manual',
    icono: Shield,
    descripcion: 'Permite analizar un correo electrónico ingresando sus datos manualmente. Ideal para pruebas rápidas.',
    pasos: [
      'Ingresa el dominio del remitente (From)',
      'Ingresa la ruta de retorno (Return-Path)',
      'Selecciona el estado de SPF y DKIM',
      'Ingresa la URL de destino del enlace',
      'Escribe el cuerpo del mensaje',
      'Especifica la extensión del adjunto (si existe)',
      'Haz clic en "Analizar Correo"',
    ],
  },
  {
    titulo: 'Análisis de CSV',
    icono: FileText,
    descripcion: 'Procesa múltiples correos desde un archivo CSV para análisis masivo.',
    pasos: [
      'Prepara un archivo CSV con las columnas: id, from_domain, return_path, spf, dkim, cuerpo_mensaje, destino_enlace, adjunto',
      'Ve a la sección "Subir CSV"',
      'Selecciona tu archivo CSV',
      'Haz clic en "Procesar CSV"',
      'Revisa los resultados y estadísticas',
    ],
  },
  {
    titulo: 'Análisis de EML',
    icono: Mail,
    descripcion: 'Sube un archivo de correo electrónico real (.eml) para extraer automáticamente sus datos y analizarlo.',
    pasos: [
      'Exporta un correo como archivo .eml desde tu cliente de correo',
      'Ve a la sección "Subir EML"',
      'Selecciona el archivo .eml',
      'Haz clic en "Escanear Correo"',
      'Revisa los resultados y hechos extraídos',
    ],
  },
];

const reglasInfo = [
  { id: 'H1', nombre: 'Inconsistencia de Dominio', descripcion: 'El dominio del remitente no coincide con la ruta de retorno' },
  { id: 'H2', nombre: 'Fallo de Autenticación', descripcion: 'SPF o DKIM fallaron en la validación' },
  { id: 'U1', nombre: 'URL con IP', descripcion: 'La URL contiene una dirección IP en lugar de un dominio' },
  { id: 'U2', nombre: 'Discrepancia de Enlace', descripcion: 'El enlace visible no coincide con el destino real' },
  { id: 'U3', nombre: 'Acortadores Sospechosos', descripcion: 'La URL usa servicios de acortamiento conocidos' },
  { id: 'S1', nombre: 'Urgencia/Amenaza', descripcion: 'El mensaje contiene lenguaje de urgencia o amenaza' },
  { id: 'S2', nombre: 'Falta de Personalización', descripcion: 'El mensaje usa saludos genéricos' },
  { id: 'A1', nombre: 'Archivo Peligroso', descripcion: 'El adjunto tiene extensión executable (.exe, .bat, etc.)' },
  { id: 'A2', nombre: 'Archivo Comprimido', descripcion: 'El adjunto es un archivo comprimido (.zip, .rar)' },
];

export default function AyudaPage() {
  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center gap-4">
        <Link href="/" className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Ayuda</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">Guía de uso del sistema PhishGuard</p>
        </div>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
            <Book className="w-5 h-5" />
            Cómo Usar el Sistema
          </h2>
        </div>
        <div className="divide-y divide-gray-200 dark:divide-gray-700">
          {secciones.map((seccion, i) => (
            <div key={i} className="p-6">
              <div className="flex items-center gap-3 mb-3">
                <seccion.icono className="w-5 h-5 text-blue-600" />
                <h3 className="font-semibold text-gray-900 dark:text-white">{seccion.titulo}</h3>
              </div>
              <p className="text-gray-600 dark:text-gray-400 mb-4">{seccion.descripcion}</p>
              <ol className="list-decimal list-inside space-y-1 text-sm text-gray-600 dark:text-gray-400">
                {seccion.pasos.map((paso, j) => (
                  <li key={j}>{paso}</li>
                ))}
              </ol>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
            <HelpCircle className="w-5 h-5" />
            Reglas Heurísticas
          </h2>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {reglasInfo.map(regla => (
              <div key={regla.id} className="p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono font-bold text-sm">{regla.id}</span>
                  <span className="font-medium text-sm">{regla.nombre}</span>
                </div>
                <p className="text-xs text-gray-500">{regla.descripcion}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}