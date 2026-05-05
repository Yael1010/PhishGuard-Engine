import os
from dotenv import load_dotenv
from supabase import create_client, Client

# Cargar las variables secretas desde el archivo .env
load_dotenv()

class SupabaseManager:
    def __init__(self):
        # Tomar las claves de las variables de entorno del sistema
        self.url = os.getenv("SUPABASE_URL")
        self.key = os.getenv("SUPABASE_KEY")
        
        if not self.url or not self.key:
            print("ADVERTENCIA: Faltan credenciales de Supabase en el archivo .env")
            
        self.supabase: Client = create_client(self.url, self.key)

    def guardar_registro(self, remitente, score, clasificacion, tipo_amenaza, reglas):
        """Inserta el resultado del análisis en la base de datos de la nube."""
        data = {
            "remitente": remitente,
            "score": score,
            "clasificacion": clasificacion,
            "tipo_amenaza": tipo_amenaza,
            "reglas_activadas": ",".join(reglas)
        }
        try:
            self.supabase.table("analisis").insert(data).execute()
        except Exception as e:
            print(f"Error al guardar en Supabase: {e}")

    def obtener_historial_completo(self):
        """Trae todos los registros ordenados por fecha de creación."""
        try:
            response = self.supabase.table("analisis").select("*").order("created_at", desc=True).execute()
            return response.data
        except Exception as e:
            print(f"Error al consultar historial: {e}")
            return []

    def obtener_resumen_estadistico(self):
        """Calcula el conteo de cada categoría para las gráficas del Dashboard."""
        historial = self.obtener_historial_completo()
        stats = {"Legítimo": 0, "Sospechoso": 0, "Malicioso": 0, "Total": len(historial)}
        
        for registro in historial:
            cat = registro.get("clasificacion")
            if cat in stats:
                stats[cat] += 1
        return stats