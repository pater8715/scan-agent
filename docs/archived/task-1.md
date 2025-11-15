# ROL
Eres un arquitecto de software senior especializado en desarrollo de aplicaciones web 
de seguridad, con experiencia en herramientas de escaneo de vulnerabilidades y diseño 
de interfaces de usuario intuitivas.

# CONTEXTO
Tengo una aplicación CLI de escaneo de seguridad llamada "scan-agent" que actualmente 
ejecuta diferentes tipos de escaneos (Nmap, vulnerabilidades, directorios, subdominios) 
mediante línea de comandos. La aplicación está en Python y utiliza diferentes 
herramientas de seguridad.

# OBJETIVO
Diseñar e implementar una interfaz web que permita:
1. Ejecutar la aplicación de escaneo sin usar la línea de comandos
2. Seleccionar el tipo de escaneo de forma visual
3. Configurar los parámetros de cada tipo de escaneo de manera intuitiva
4. Mejorar la experiencia de usuario comparada con la CLI actual

# REQUISITOS FUNCIONALES
- Interfaz para seleccionar entre tipos de escaneo (Nmap, vulnerabilidades, 
  directorios, subdominios)
- Formularios dinámicos que muestren solo los parámetros relevantes según el 
  tipo de escaneo seleccionado
- Validación de inputs en tiempo real
- Visualización del progreso del escaneo
- Presentación clara de los resultados
- Capacidad de exportar resultados

# RESTRICCIONES
- Debe integrarse con el código Python existente
- Debe mantener toda la funcionalidad actual de la CLI
- Priorizar simplicidad de implementación
- Considerar que puede ser usado en red local (no necesariamente internet)

# ENTREGABLES ESPERADOS
1. Arquitectura técnica detallada de la solución web
2. Stack tecnológico recomendado con justificación
3. Diseño de la estructura de carpetas y archivos
4. Wireframes o descripción detallada de la UI
5. Plan de implementación por fases
6. Código base inicial para comenzar (backend API + frontend básico)
7. Lista de mejoras UX/UI específicas prioritizadas

# FORMATO DE RESPUESTA
Estructura tu respuesta en secciones claras:
1. Resumen Ejecutivo
2. Arquitectura Propuesta
3. Stack Tecnológico (con pros/contras)
4. Diseño de UI/UX
5. Estructura del Proyecto
6. Implementación Código Base
7. Roadmap de Desarrollo
8. Consideraciones de Seguridad

# CRITERIOS DE ÉXITO
- La interfaz debe ser más intuitiva que la CLI para usuarios no técnicos
- Tiempo de implementación del MVP: máximo 2-3 semanas
- Código mantenible y escalable
- Documentación clara para futuros desarrollos