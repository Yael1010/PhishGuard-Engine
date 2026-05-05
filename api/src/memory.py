class MemoriaDeTrabajo:
    def __init__(self):
        self.hechos_iniciales = {}
        self.puntaje_riesgo = 0
        self.clasificacion_final = "Legítimo"
        self.tipo_amenaza = "Ninguno" # <-- NUEVA VARIABLE
        self.reglas_activadas = []

    def cargar_hechos(self, datos_extraidos):
        self.hechos_iniciales = datos_extraidos

    def registrar_activacion(self, id_regla, peso, descripcion):
        self.puntaje_riesgo += peso
        self.reglas_activadas.append({
            "regla": id_regla,
            "peso_sumado": peso,
            "detalle": descripcion
        })

    def obtener_estado_actual(self):
        return {
            "score_actual": self.puntaje_riesgo,
            "reglas_disparadas": self.reglas_activadas,
            "tipo_amenaza": self.tipo_amenaza # <-- PASAMOS LA VARIABLE A LA INTERFAZ
        }