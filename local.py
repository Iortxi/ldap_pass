
import subprocess, os, signal, psutil
from utils import soltar_error
from argparse import Namespace


class Local:
    """ Clase con los metodos relacionados con el tratamiento de archivos y procesos de ejecucion. """

    @staticmethod
    def verificar_interfaz_red(args: Namespace) -> None:
        """
        Finaliza la ejecucion si la interfaz de red que ha introducido el usuario no existe.

        Args:
            args: Espacio de nombres con los argumentos de ejecucion.
        """

        # Diccionario con los nombres de las interfaces de red y su informacion
        interfaces = psutil.net_if_addrs()

        # Si la interfaz de red introducida no existe, la ejecucion termina
        if not args.interface in interfaces:
            soltar_error(f'Network interface {args.interface} does not exist', 1)



    @staticmethod
    def comando_ok(comando: str) -> bool:
        """
        Ejecuta un comando localmente.

        Args: 
            comando: Cadena de texto del comando a ejecutar.

        Returns:
            bool: True si el comando se ha ejecutado correctamente.
        """

        # Se ejecuta el comando y se espera a que acabe
        p = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return p.returncode == 0



    @staticmethod
    def comando_escuchador(args: Namespace, listeners: dict) -> str:
        """
        Busca que comando de escucha existe en la maquina local.

        Args:
            args: Espacio de nombres con los argumentos de ejecucion.
            listeners: Diccionario con las plantillas de ejecucion de los comandos de escucha disponibles.

        Returns:
            str: Cadena de texto con el comando a ejeutar localmente para escuchar trafico, en otro caso finaliza la ejecucion.
        """

        # Unix, MacOS
        if os.name == 'posix':
            donde = 'which'

        # Windows
        else:
            donde = 'where'


        # Primero se prueba el comando escuchador especificado por el usuario, si no funciona, se muestra warning y se prueba el resto
        if args.command and args.command in listeners and Local.comando_ok(f'{donde} {args.command}'):

            """ ESTO SE REPITE ABAJO TMBN, FUNCION EN CLASE Trafico """
            # Comando a ejecutar para capturar trafico sin filtrar por puerto
            com = listeners[args.command][0].replace('INTERFAZ', args.interface).replace('NOMBRE', f'{args.filename}_temp')

            # Si se ha especificado un puerto, se agnade al comando
            if args.port:
                com += f'{listeners[args.command][1].replace('PUERTO', str(args.port))}'

            return com

        else:
            print('[!] WARNING: Specified listener command does not exist. Trying with the others supported')


        # Se itera sobre los programas de escucha disponibles. Se usa el primero que exista
        for escuchador in listeners.keys():
            if Local.comando_ok(f'{donde} {escuchador}'):
                # Comando a ejecutar para capturar trafico sin filtrar por puerto
                com = listeners[args.command][0].replace('INTERFAZ', args.interface).replace('NOMBRE', f'{args.filename}_temp')

                # Si se ha especificado un puerto, se agnade al comando
                if args.port:
                    com += f'{listeners[args.command][1].replace('PUERTO', str(args.port))}'

                return com

        # Ningun programa de escucha de los disponibles existe en la maquina remota
        soltar_error('Any of the listeners supported are available on local host', 5)



    @staticmethod
    def iniciar_captura(comando: str) -> int:
        """
        Inicia un proceso en segundo plano con un programa de captura.

        Args:
            comando: Cadena de texto con el comando de escucha a ejecutar.

        Returns:
            int: Devuelve el PID del proceso del comando ejecutado.
        """

        proceso_captura = subprocess.Popen(comando, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return proceso_captura.pid



    @staticmethod
    def parar_captura(pid: int) -> None:
        """
        Detiene el proceso de captura de trafico.

        Args:
            pid: PID del proceso a detener.
        """

        # Se envia la segnal al proceso de captura para que se detenga
        os.kill(pid, signal.SIGTERM)

        try:
            # Se comprueba si el proceso sigue vivo
            os.kill(pid, 0)
        
        # Si salta alguna excepcion, el proceso se ha detenido correctamente
        except:
            pass

        # Si no salta ninguna excepcion es que el proceso sigue vivo, se fuerza a que acabe con SIGKILL
        else:
            os.kill(pid, signal.SIGKILL)
