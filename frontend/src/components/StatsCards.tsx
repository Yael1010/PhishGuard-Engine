'use client';

import type { Estadisticas } from '@/types';

interface StatsCardsProps {
  stats: Estadisticas | null;
  loading?: boolean;
}

export function StatsCards({ stats, loading }: StatsCardsProps) {
  if (loading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        {[1, 2, 3, 4].map(i => (
          <div key={i} className="bg-white dark:bg-gray-800 p-4 rounded-xl border border-gray-200 dark:border-gray-700 animate-pulse">
            <div className="h-4 w-24 bg-gray-200 dark:bg-gray-700 rounded mb-2"></div>
            <div className="h-8 w-16 bg-gray-200 dark:bg-gray-700 rounded"></div>
          </div>
        ))}
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-white dark:bg-gray-800 p-4 rounded-xl border border-gray-200 dark:border-gray-700 border-l-4 border-l-blue-500">
          <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Total Histórico</p>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">0</p>
        </div>
        <div className="bg-white dark:bg-gray-800 p-4 rounded-xl border border-gray-200 dark:border-gray-700 border-l-4 border-l-green-500">
          <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Legítimos</p>
          <p className="text-2xl font-bold text-green-600 dark:text-green-400">0</p>
        </div>
        <div className="bg-white dark:bg-gray-800 p-4 rounded-xl border border-gray-200 dark:border-gray-700 border-l-4 border-l-yellow-400">
          <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Sospechosos</p>
          <p className="text-2xl font-bold text-yellow-500 dark:text-yellow-400">0</p>
        </div>
        <div className="bg-white dark:bg-gray-800 p-4 rounded-xl border border-gray-200 dark:border-gray-700 border-l-4 border-l-red-500">
          <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Maliciosos</p>
          <p className="text-2xl font-bold text-red-600 dark:text-red-400">0</p>
        </div>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
      <div className="bg-white dark:bg-gray-800 p-4 rounded-xl border border-gray-200 dark:border-gray-700 border-l-4 border-l-blue-500">
        <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Total Histórico</p>
        <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.Total}</p>
      </div>
      <div className="bg-white dark:bg-gray-800 p-4 rounded-xl border border-gray-200 dark:border-gray-700 border-l-4 border-l-green-500">
        <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Legítimos</p>
        <p className="text-2xl font-bold text-green-600 dark:text-green-400">{stats.Legítimo}</p>
      </div>
      <div className="bg-white dark:bg-gray-800 p-4 rounded-xl border border-gray-200 dark:border-gray-700 border-l-4 border-l-yellow-400">
        <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Sospechosos</p>
        <p className="text-2xl font-bold text-yellow-500 dark:text-yellow-400">{stats.Sospechoso}</p>
      </div>
      <div className="bg-white dark:bg-gray-800 p-4 rounded-xl border border-gray-200 dark:border-gray-700 border-l-4 border-l-red-500">
        <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Maliciosos</p>
        <p className="text-2xl font-bold text-red-600 dark:text-red-400">{stats.Malicioso}</p>
      </div>
    </div>
  );
}