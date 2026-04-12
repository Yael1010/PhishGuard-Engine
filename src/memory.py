class MemoriaDeTrabajo:
    def __init__(self):
        # Hechos dinámicos extraídos del correo
        self.hechos_iniciales = {}
        
        # Variables de control (Acumuladores)
        self.puntaje_riesgo = 0
        self.clasificacion_final = "Legítimo"
        
        # Historial para el Módulo de Explicación (Backward Chaining)
        self.reglas_activadas = []

    def cargar_hechos(self, datos_extraidos):
        """
        Recibe un diccionario con las variables extraídas del correo 
        (ej. dominio_remitente, enlaces, etc.) y las guarda en la memoria.
        """
        self.hechos_iniciales = datos_extraidos

    def registrar_activacion(self, id_regla, peso, descripcion):
        """
        Cada vez que el Motor de Inferencia dispara una regla, 
        se llama a esta función para sumar los puntos y guardar el log.
        """
        self.puntaje_riesgo += peso
        self.reglas_activadas.append({
            "regla": id_regla,
            "peso_sumado": peso,
            "detalle": descripcion
        })

    def obtener_estado_actual(self):
        """Devuelve un resumen del análisis hasta el momento."""
        return {
            "score_actual": self.puntaje_riesgo,
            "reglas_disparadas": self.reglas_activadas
        }