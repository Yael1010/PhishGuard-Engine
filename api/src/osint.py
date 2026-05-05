import whois
from datetime import datetime
import tldextract

class AnalizadorOSINT:
    def __init__(self):
        pass

    def obtener_edad_dominio(self, dominio):
        """
        Consulta la base de datos WHOIS de forma precisa usando tldextract 
        para no romper dominios ccTLD (como .edu.mx o .com.mx).
        """
        if not dominio or '@' in dominio:
            return None 
            
        try:
            # tldextract separa el dominio real del sufijo sin importar cuántos puntos tenga
            ext = tldextract.extract(dominio)
            dominio_raiz = f"{ext.domain}.{ext.suffix}"
            
            # Si es una IP pura o un texto sin sentido, detenemos la consulta
            if not ext.domain or not ext.suffix:
                return None

            info = whois.whois(dominio_raiz)
            
            fecha_creacion = info.creation_date
            # A veces WHOIS devuelve una lista de fechas si el dominio ha sido transferido
            if isinstance(fecha_creacion, list):
                fecha_creacion = fecha_creacion[0]

            if fecha_creacion:
                # Si la fecha viene como string, intentamos procesarla (prevención de errores)
                if isinstance(fecha_creacion, str):
                    try:
                        fecha_creacion = datetime.strptime(fecha_creacion, "%Y-%m-%d")
                    except ValueError:
                        return None
                        
                fecha_creacion = fecha_creacion.replace(tzinfo=None)
                hoy = datetime.now()
                diferencia = hoy - fecha_creacion
                return diferencia.days
            
            return None
            
        except Exception as e:
            print(f"Error consultando WHOIS para {dominio}: {e}")
            return None