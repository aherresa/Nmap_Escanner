#PROYECTO FINAL:ANDRÉS FELIPE HERRERA SALAZAR
# Escáner de vulnerabilidades con Python-Nmap y scripts NSE, con salida embellecida

# Importaciones necesarias para el escáner de vulnerabilidades
import nmap          # Librería principal para ejecutar comandos nmap desde Python
import sys           # Para controlar la salida del programa y argumentos del sistema
import os            # Para ejecutar comandos del sistema operativo
from tqdm import tqdm                    # Barra de progreso visual durante el escaneo
from rich.console import Console         # Para salida con colores y formato elegante
from rich.panel import Panel             # Para crear paneles con bordes decorativos
from rich.text import Text               # Para texto con formato rich
from pyfiglet import Figlet              # Para crear el banner ASCII del programa
from rich.table import Table             # Para mostrar resultados en formato de tabla
from rich import box                     # Estilos de cajas para las tablas

# Inicializar la consola de Rich para output con colores
console = Console()

def print_banner():
    """
    Función que muestra el banner de bienvenida del programa.
    Utiliza pyfiglet para crear texto ASCII artístico y rich para los colores.
    """
    # Crear el generador de texto ASCII con fuente 'slant'
    fig = Figlet(font='slant')
    # Generar el banner con el nombre del programa
    banner = fig.renderText('NMAP ANDRES H.')
    # Mostrar el banner en color cyan
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    # Mostrar un panel descriptivo con el propósito del programa
    console.print(Panel("💻 [bold blue]Escáner de Vulnerabilidades NSE con Nmap[/bold blue]", style="bold cyan"))

def chunk_ports(start, end, size=50):
    """
    Divide el rango de puertos en bloques más pequeños para evitar timeouts.
    
    Args:
        start (int): Puerto inicial del rango
        end (int): Puerto final del rango  
        size (int): Tamaño de cada bloque (por defecto 50 puertos)
    
    Returns:
        list: Lista de strings con rangos de puertos (ej: ["1-50", "51-100"])
    
    Ejemplo: chunk_ports(1, 150, 50) devuelve ["1-50", "51-100", "101-150"]
    """
    return [f"{i}-{min(i + size - 1, end)}" for i in range(start, end + 1, size)]

def run_nmap_scan(target, port_chunks):
    """
    Ejecuta el escaneo de nmap por bloques de puertos para evitar saturar la red.
    
    Args:
        target (str): IP o dominio objetivo del escaneo
        port_chunks (list): Lista de rangos de puertos a escanear
    
    Returns:
        nmap.PortScanner: Objeto con todos los resultados del escaneo
    """
    # Inicializar el objeto PortScanner de python-nmap
    nm = nmap.PortScanner()
    # Mostrar mensaje informativo sobre el inicio del escaneo
    console.print(Panel.fit(f"[bold cyan]🔍 Escaneando {target} por bloques de puertos...[/bold cyan]", style="blue"))

    # Crear barra de progreso que muestra el avance del escaneo
    with tqdm(total=len(port_chunks), desc="Progreso del escaneo") as pbar:
        # Iterar sobre cada bloque de puertos
        for port_range in port_chunks:
            # Actualizar la barra de progreso con el rango actual
            pbar.set_postfix(puerto=port_range)
            try:
                # Ejecutar nmap con detección de servicios (-sV) y scripts de vulnerabilidades (--script vuln)
                nm.scan(hosts=target, ports=port_range, arguments='-sV --script vuln')
            except nmap.PortScannerError as e:
                # Capturar errores específicos de nmap (puerto inválido, host inalcanzable, etc.)
                console.print(f"[bold red]⚠️ Error al escanear puertos {port_range}: {e}[/bold red]")
            except Exception as e:
                # Capturar cualquier otro error inesperado
                console.print(f"[bold red]⚠️ Error inesperado en puertos {port_range}: {e}[/bold red]")
            # Incrementar la barra de progreso
            pbar.update(1)

    return nm

def analyze_results(nm):
    """
    Analiza los resultados del escaneo de nmap y extrae información relevante.
    
    Args:
        nm (nmap.PortScanner): Objeto con los resultados del escaneo
    
    Returns:
        list: Lista de diccionarios con información de cada puerto/vulnerabilidad encontrada
    """
    vulnerabilities = []  # Lista para almacenar todos los hallazgos
    
    # Iterar sobre todos los hosts escaneados (normalmente será uno solo)
    for host in nm.all_hosts():
        # Mostrar información básica del host
        console.print(Panel(f"[bold green]📡 Host: {host} – Estado: {nm[host].state()}[/bold green]", style="green"))

        # Iterar sobre todos los protocolos encontrados (TCP, UDP)
        for proto in nm[host].all_protocols():
            # Obtener los datos de todos los puertos para este protocolo
            ports_data = nm[host][proto]
            
            # Analizar cada puerto individualmente
            for port, pdata in ports_data.items():
                # Extraer información básica del puerto
                state = pdata['state']                    # Estado: open, closed, filtered
                service = pdata.get('name', 'desconocido') # Nombre del servicio (http, ssh, etc.)
                version = pdata.get('version', 'N/A')     # Versión del servicio
                product = pdata.get('product', 'N/A')     # Producto específico (Apache, OpenSSH, etc.)
                scripts = pdata.get('script', {})         # Resultados de los scripts NSE

                # Solo procesar puertos abiertos
                if state == 'open':
                    # Si hay resultados de scripts NSE (potenciales vulnerabilidades)
                    if scripts:
                        # Crear una entrada por cada script ejecutado
                        for script, output in scripts.items():
                            entry = {
                                "host_port": f"{host}:{port}",
                                "servicio": f"{service} ({product} {version})".strip(),
                                "estado": state,
                                "script": script,
                                "resultado": output.strip()
                            }
                            vulnerabilities.append(entry)
                    else:
                        # Puerto abierto pero sin hallazgos de scripts NSE
                        entry = {
                            "host_port": f"{host}:{port}",
                            "servicio": f"{service} ({product} {version})".strip(),
                            "estado": state,
                            "script": "N/A",
                            "resultado": "Puerto abierto, sin hallazgos NSE"
                        }
                        vulnerabilities.append(entry)

    return vulnerabilities

def print_summary(vulns):
    """
    Muestra un resumen organizado de todos los hallazgos en formato de tabla.
    
    Args:
        vulns (list): Lista de diccionarios con la información de vulnerabilidades
    """
    # Mostrar separador visual
    console.rule("[bold magenta]🛡️ Resultados del Escaneo de Vulnerabilidades")

    # Si no se encontraron puertos abiertos o vulnerabilidades
    if not vulns:
        console.print(Panel("[green]✅ No se encontraron puertos abiertos o vulnerabilidades con los scripts NSE de Nmap.[/green]", style="green"))
        return

    # Crear la tabla principal con formato profesional
    table = Table(
        show_header=True,                # Mostrar encabezados de columna
        header_style="bold magenta",     # Estilo de los encabezados
        title="📋 [bold yellow]Resumen de Vulnerabilidades[/bold yellow]",
        title_justify="center",          # Centrar el título
        show_lines=True,                 # Mostrar líneas entre filas
        box=box.ROUNDED                  # Estilo de borde redondeado
    )
    
    # Definir las columnas de la tabla con sus estilos
    table.add_column("#", style="bold blue", width=4, justify="center")        # Índice numerado
    table.add_column("Host:Puerto", style="cyan", no_wrap=True)                # IP y puerto
    table.add_column("Servicio", style="green")                               # Nombre del servicio
    table.add_column("Estado", style="yellow", width=8)                       # Estado del puerto
    table.add_column("Script NSE", style="magenta")                           # Script ejecutado
    table.add_column("Resultado", style="white")                              # Output del script

    # Llenar la tabla con los datos encontrados
    for i, v in enumerate(vulns, 1):  # enumerate comenzando en 1 para el índice
        resultado = v["resultado"]
        # Truncar resultados muy largos para mantener la tabla legible
        if len(resultado) > 80:
            resultado = resultado[:77] + "..."
        
        # Agregar fila con todos los datos
        table.add_row(
            str(i),              # Número de fila
            v["host_port"],      # Host:Puerto
            v["servicio"],       # Información del servicio
            v["estado"],         # Estado del puerto
            v["script"],         # Script NSE ejecutado
            resultado            # Resultado (truncado si es necesario)
        )

    # Mostrar la tabla principal
    console.print(table)
    
    # Calcular estadísticas del escaneo
    total_puertos = len(vulns)
    vulnerabilidades_reales = sum(1 for v in vulns if v["script"] != "N/A")
    
    # Crear tabla de estadísticas
    stats_table = Table(
        show_header=True,
        header_style="bold cyan",
        title="📊 [bold green]Estadísticas del Escaneo[/bold green]",
        box=box.SIMPLE
    )
    stats_table.add_column("Métrica", style="bold white")
    stats_table.add_column("Valor", style="bold yellow")
    
    # Agregar las métricas calculadas
    stats_table.add_row("Total de puertos abiertos", str(total_puertos))
    stats_table.add_row("Scripts NSE ejecutados", str(vulnerabilidades_reales))
    stats_table.add_row("Puertos sin hallazgos", str(total_puertos - vulnerabilidades_reales))
    
    console.print(stats_table)
    
    # Mostrar mensaje final basado en los resultados
    if vulnerabilidades_reales > 0:
        console.rule("[bold red]⚠️ Se detectaron hallazgos con scripts NSE")
    else:
        console.rule("[bold green]✅ No se detectaron vulnerabilidades")

def export_to_file(vulns, filename="nmap_results.txt"):
    """
    Exporta los resultados del escaneo a un archivo de texto plano.
    
    Args:
        vulns (list): Lista con los hallazgos del escaneo
        filename (str): Nombre del archivo donde guardar (por defecto: nmap_results.txt)
    """
    try:
        # Abrir archivo en modo escritura con codificación UTF-8
        with open(filename, 'w', encoding='utf-8') as f:
            # Escribir encabezado del reporte
            f.write("=== REPORTE DE ESCANEO NMAP ===\n\n")
            
            # Escribir cada hallazgo numerado
            for i, v in enumerate(vulns, 1):
                f.write(f"{i}. {v['host_port']}\n")
                f.write(f"   Servicio: {v['servicio']}\n")
                f.write(f"   Estado: {v['estado']}\n")
                f.write(f"   Script: {v['script']}\n")
                f.write(f"   Resultado: {v['resultado']}\n")
                f.write("-" * 50 + "\n")  # Separador entre entradas
                
        # Confirmar que el archivo se guardó correctamente
        console.print(f"[bold green]✅ Resultados exportados a: {filename}[/bold green]")
    except Exception as e:
        # Manejar errores de escritura de archivo
        console.print(f"[bold red]❌ Error al exportar: {e}[/bold red]")

def main():
    if os.system("which nmap >/dev/null 2>&1") != 0:
        console.print("[bold red]❌ Nmap no está instalado. Instala con:[/bold red]\n[cyan]sudo apt update && sudo apt install nmap python3-nmap[/cyan]")
        sys.exit(1)

    os.system("clear" if os.name == "posix" else "cls")
    print_banner()

    target = console.input("[bold purple]📥 IP o dominio objetivo:[/bold purple] ").strip()
    try:
        start = int(console.input("[bold purple]🔢 Puerto inicial (ej. 1):[/bold purple] "))
        end = int(console.input("[bold purple]🔢 Puerto final   (ej. 1024):[/bold purple] "))
        if end < start:
            raise ValueError()
    except ValueError:
        console.print("[bold red]❌ Debes ingresar un rango de puertos válido.[/bold red]")
        sys.exit(1)

    port_chunks = chunk_ports(start, end, size=50)
    nm = run_nmap_scan(target, port_chunks)
    vulns = analyze_results(nm)
    print_summary(vulns)
    
    # Opción de exportar
    if vulns:
        export_choice = console.input("\n[bold purple]¿Exportar resultados a archivo? (s/n):[/bold purple] ").strip().lower()
        if export_choice in ['s', 'si', 'yes', 'y']:
            filename = console.input("[bold purple]Nombre del archivo (Enter para 'nmap_results.txt'):[/bold purple] ").strip()
            if not filename:
                filename = "nmap_results.txt"
            export_to_file(vulns, filename)

if __name__ == "__main__":
    main()