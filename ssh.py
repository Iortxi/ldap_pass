
import paramiko, os, time
from utils import soltar_error
from argparse import Namespace


class SSH:
    """ Clase con los metodos relacionados con las conexiones SSH de Paramiko. """

    @staticmethod
    def conectarse_a_host(args: Namespace) -> tuple[paramiko.SSHClient, paramiko.SFTPClient]:
        """
        Establece una conexion SSH con un servidor.

        Args:
            args: Espacio de nombres con los argumentos de ejecucion.

        Returns:
            tuple: Tupla con los sockets de la conexion (SSH, SFTP), o finaliza la ejecucion si la conexion falla (autenticacion, timeout, etc).
        """

        # No se ha especificado ningun metodo de autenticacion
        if not args.pkfile and not args.password:
            soltar_error('Password or private key file required (authentication)', 1)

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Si se especifica una clave privada, paramiko la busca y salta excepcion si no existe, aunque se haya introducido una contrasegna correcta
        if args.pkfile and not os.path.isfile(args.pkfile):
            args.pkfile = None

        # Autenticacion por contrasegna o clave privada
        try:
            ssh.connect(hostname=args.server, username=args.user, port=args.ssh_port, password=args.password, key_filename=args.pkfile, passphrase=args.pkfilepw)
        except paramiko.AuthenticationException:
            soltar_error('SSH authentication failed', 2)
        except:
            soltar_error('SSH session could not be established for no authentication reason', 3)

        return ssh, ssh.open_sftp()



    @staticmethod
    def verificar_interfaz_red_remota(ssh: paramiko.SSHClient, args: Namespace) -> None:
        """
        Termina la ejecucion si la interfaz de red especificada por el usuario no existe en el servidor remoto.

        Args:
            ssh: Socket de conexion SSH.
            args: Espacio de nombres con los argumentos de ejecucion.
        """

        # Comando a ejecutar remotamente ('ifconfig -a' funciona en todos los SO basados en UNIX)
        comando = f'ifconfig -a | grep "{args.interface}: flags="'

        if not SSH.comando_ok(ssh, comando):
            soltar_error('Remote network interface does not exist', 5)



    @staticmethod
    def recoger_y_borrar_captura(ssh: paramiko.SSHClient, scp: paramiko.SFTPClient, args: Namespace) -> None:
        """
        Transfiere la captura remota y la borra en el servidor remoto.

        Args:
            ssh: Socket de conexion SSH.
            scp: Socket de conexion SFTP.
            args: Espacio de nombres con los argumentos de ejecucion.
        """

        nombre_temporal = f'{args.filename}_temp'

        # Recoger captura guardada remotamente
        scp.get(f'/tmp/{args.filename}', f'./{nombre_temporal}')
        
        # Borrar captura remota
        SSH.comando_ok(ssh, f'rm -f /tmp/{args.filename}')
        # del /f /q FICHERO -> Equivalente en Windows a rm -f FICHERO



    @staticmethod
    def comando_ok(ssh: paramiko.SSHClient, comando: str) -> bool:
        """
        Ejecuta remotamente un comando.

        Args:
            ssh: Socket de conexion SSH.
            comando: Cadena de texto con el comando a ejecutar remotamente.

        Returns:
            bool: True si el comando se ha ejecutado correctamente, False en caso contrario.
        """

        # Ejecuta un comando pero no espera a que acabe
        _, stdout, _ = ssh.exec_command(f'bash -lc "{comando}"')
        
        # Espera a que el comando termine y saca su codigo de salida
        codigo_salida = stdout.channel.recv_exit_status()

        return codigo_salida == 0



    @staticmethod
    def comando_remoto(ssh: paramiko.SSHClient, args: Namespace, listeners: dict) -> str:
        """
        Comprueba que programa de captura de trafico existe en el servidor remoto.

        Args:
            ssh: Socket de conexion SSH.
            args: Espacio de nombres con los argumentos de ejecucion.
            listeners: Diccionario con las plantillas de ejecucion de los comandos de escucha disponibles.

        Returns:
            str: Cadena de texto del comando a ejecutar en el servidor remoto para escuchar trafico.
        """

        # Mostrar que escuchador se va a usar
        mostrar = False

        # Primero se prueba el comando escuchador especificado por el usuario, si no funciona, se muestra warning y se prueba el resto
        if args.command:
            if SSH.comando_ok(ssh, f'which {args.command}'):
                # Comando a ejecutar para capturar trafico sin filtrar por puerto
                com = listeners[args.command][0].replace('INTERFAZ', args.interface).replace('NOMBRE', args.filename)

                # Si se ha especificado un puerto, se agnade al comando
                if args.port:
                    com += f' {listeners[args.command][1].replace('PUERTO', str(args.port))}'

                return com
            else:
                mostrar = True
                print('[!] WARNING: Specified listener command is not available on remote host. Trying with the others supported\n')


        # Se itera sobre los programas de escucha disponibles. Se usa el primero que exista en la maquina remota
        for escuchador in listeners.keys():
            if SSH.comando_ok(ssh, f'which {escuchador}'):
                if mostrar:
                    # Se muestra el escuchador que se usara para la captura
                    print(f'[+] Using listener: {escuchador}\n')

                # Comando a ejecutar para capturar trafico sin filtrar por puerto y con nombre temporal para la captura
                com = listeners[escuchador][0].replace('INTERFAZ', args.interface).replace('NOMBRE', args.filename)

                # Si se ha especificado un puerto, se agnade al comando
                if args.port:
                    com += f' {listeners[escuchador][1].replace('PUERTO', str(args.port))}'

                return com

        # Ningun programa de escucha de los disponibles existe en la maquina remota
        soltar_error('Any of the listeners supported are available on remote host', 5)



    @staticmethod
    def iniciar_captura(ssh: paramiko.SSHClient, comando_remoto: str) -> int:
        """
        Inicia un proceso de captura remoto con el programa de captura disponible.

        Args:
            ssh: Socket de conexion SSH.
            comando_remoto: Cadena de texto con el comando de captura a ejecutar remotamente.

        Returns:
            int: PID del proceso de captura iniciado.
        """

        # Comando que se va a dejar ejecutandose remotamente (nohup)
        comando = f'nohup {comando_remoto} > /dev/null 2>&1 & echo $!'

        # Se lanza el comando y se obtiene su PID
        _, stdout, _ = ssh.exec_command(comando)
        pid = stdout.read().decode().strip()

        # if not pid.isdigit():
        #         # Buscar el proceso por nombre del comando
        #         stdin2, stdout2, stderr2 = client.exec_command(f"pgrep -f '{comando_remoto.split()[0]}' || true")
        #         pids = stdout2.read().decode().strip().split()
        #         pid = pids[0] if pids else ""
        #     if not pid:
        #         "No se pudo obtener el PID remoto"

        return int(pid)



    @staticmethod
    def parar_captura(ssh: paramiko.SSHClient, pid: int, timeout: int = 3) -> None:
        """
        Detiene el proceso de captura de trafico remoto.

        Args:
            ssh: Socket de conexion SSH.
            pid: Entero con el PID del proceso remoto a detener.
            timeout: Entero con el tiempo en segundos a esperar para comprobar si el proceso remoto se ha detenido.
        """

        # Se intenta finalizar el proceso con la segnal SIGTERM
        ssh.exec_command(f'kill -TERM {pid} || true')
        time.sleep(timeout)

        # Verificamos si sigue vivo
        _, stdout, _ = ssh.exec_command(f'ps -p {pid} -o pid=')
        alive = stdout.read().decode().strip()

        # if alive:
        #     soltar_error('RAROOOOOO', 9)
        #     # Si sigue vivo, se fuerza con SIGKILL
        #     client.exec_command(f'kill -KILL {pid} || true')
