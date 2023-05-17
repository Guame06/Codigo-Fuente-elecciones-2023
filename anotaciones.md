# Structs

app/msa/core/armve/structs.py
```python
struct_tag_header = Struct("tag_header",
                           UBInt8("token"),
                           UBInt8("tipo_tag"),
                           UBInt16("size"))
struct_tag = Struct("tag",
                    Embed(struct_tag_header),
                    Bytes("crc32", 4),
                    Bytes("user_data", lambda ctx: ctx.size))

```

Los datos del voto se guardan dentro del campo "user_data", inicialmente no hemos encontrado evidencia de que la fecha y hora del voto existen dentro del campo "user_data", de esta forma concluimos que existe una vulnerabilidad de seguridad, debido a que no es posible auditar la fecha y hora de cada voto, abriendo una brecha donde en ciertas mesas existen mas de 389 votos cuyos certificados TREP estan registrados en horarios que no cierran con la cantidad de votos de la mesa y el tiempo que llevaria tener esos votos, luego hacer el escrutinio y por ultimo enviar los certificados de resultado al sistema TREP.

# Apertura
app/msa/modulos/sufragio/__init__.py

```python
    """
        Módulo de votación.

        Espera a que se aproxime un tag, si esta vacío permite votar, sino
        muestra el contenido del tag.

        Si durante cualquier momento de la votación, se retira el tag, cancela
        la operación y vuelve a la pantalla de espera.
    """
    @requiere_mesa_abierta
    def __init__(self, nombre, activar_presencia=None):
    	self.web_template = "sufragio"
        self.registrador = Registrador(self._fin_registro, self, self._error)
        # Inicio presencia por única vez en el módulo
        self.start_presencia()
```

# Registrador
app/msa/modulos/sufragio/registrador.py
```python
    def registrar_voto(self, solo_imprimir=False):
        """
        La función que explícitamente manda a registrar el voto.

        Args:
            solo_imprimir (bool): Determina si solamente se graba el tag o no.
        """
        self.logger.info("Registrando voto.")
        self.modulo.rampa.set_led_action('impresion')
        rampa = self.modulo.rampa
        self._start = datetime.now()

        self._evento_ya_lanzado = False
        if rampa.tiene_conexion:
            rampa.registrar_fin_impresion(self._fin_de_la_impresion)

            self.logger.info("Enviando comando de impresion.")
            # traemos la key de encriptación del voto.
            aes_key = self.modulo.sesion.mesa.get_aes_key()
            # Guardamos el tag e imprimimos la boleta.
            rampa.registrar_error_impresion(self._error_impresion)
            rampa.registrar_voto(self.seleccion, solo_imprimir, aes_key,
                                 self._evaluar_grabacion_tag)
        else:
            self.callback_error()
```

# Rampa
La rampa es una abstraccion que sirve de interfaz entre las acciones disponibles en el sistema, en este caso la accion que debemos observar es "registrar_voto", el parametro "seleccion" tiene los candidatos seleccionados en el voto

app/msa/modulos/sufragio/rampa.py
```python
    def registrar_voto(self, seleccion, solo_imprimir, aes_key, callback):
        """
        Registra un voto en una BUE (Boleta Única Electrónica)

        Args:

            seleccion (dict): Contiene la selección de los candidatos.
            imprimir (bool): Por si se desea imprimir pero no guarda en el tag.
            aes_key (bytes): Clave con la cual se encriptan los votos.
            callback (function):  el callback que vamos a llamar cuando termine
                el poceso de registro.

        Returns:
            ?

        """
        respuesta = self._servicio.registrar_voto(seleccion, solo_imprimir,
                                                  aes_key, callback)
        return respuesta
```

El metodo "self._servicio.registrar_voto" tiene como objetivo llamar IPCClient.registrar_voto, enviando una instancia de la clase "Seleccion" como parametro, no se registra la fecha y hora del voto en cuestion.




# Cliente - Seccion donde se llama un metodo por IPC al service
Esta clase representa el servicio que realizada la escritura del tag RFID, se tiene el metodo "registrar_voto", este metodo recibe como parametros una "seleccion" y una llave "aes_key", se puede verificar que no se agrega en ningun parametro o un campo que represente la fecha y hora del voto en cuestion.

app/msa/core/ipc/client/__init__.py
```python
class IPCClient(IPC):
    """Cliente que interactúa con con :meth:`core.ipc.server.IPCServer <core.ipc.server.IPCServer>`."""
    def registrar_voto(self, seleccion, solo_imprimir, aes_key, callback):
        """Registra (Guarda el tag + imprime el papel) el voto.
        Llama a un callback con el estado cuanto termina de registrar.

        Argumentos:
            seleccion -- el objeto Seleccion con el voto que queremos grabar.
            solo_imprimir -- si queremos imprimir pero no guardar el tag.
            aes_key -- la clave aes con la que vamos a encriptar.
            callback -- el callback que vamos a llamar cuando termine el
                proceso de registro
        """
        tag = b64encode(seleccion.a_tag())
        aes_key = b64encode(aes_key)
        params = [tag, solo_imprimir, aes_key]
        if seleccion.mesa:
            params.append(seleccion.mesa.codigo)
            params.append(True) # convertir mesa a objeto Ojota
        self.call_async("registrar", callback, params)
```

El cliente codifica la instancia de la clase "Seleccion" en 2 pasos:
1 - hace una llamada al metodo "a_tag()" de la instancia seleccion de la clase Seleccion
2 - utilizar el resultado de (1) para luego llamar la funcion "b64encode" para codificar la informacion a base 64
3 - se llama un metodo por IPC, en este caso el metodo "registrar"

## Clase Seleccion
En el metodo "a_tag()" no se puede ver de forma explicita alguna variable que pueda almacenar la fecha y la hora de la creacion del voto

```python
class Seleccion(object):

    """Seleccion de candidatos (voto)."""
    def a_tag(self):
        """Devuelve la informacion de la seleccion para almacenar en tag rfid.
        """
        # Generamos el largo del codigo de ubicacion de la mesa
        # Y los votos de cada categoria (lista de id_umv de candidaturas)
        votos_categorias = self._votos_categorias()
        tachas = self._tachas()
        preferencias = self._preferencias()

        ubicacion = bytes(self.mesa.cod_datos, "ascii")
        len_ubic = bytes(str(len(ubicacion)).zfill(LEN_LEN_UBIC), "ascii")
        opciones = votos_categorias
        len_opciones = bytes(str(len(opciones)).zfill(LEN_LEN_OPC), "ascii")
        len_preferencias = bytes(str(len(preferencias)).zfill(LEN_LEN_TAC), "ascii")
        len_tachas = bytes(str(len(tachas)).zfill(LEN_LEN_TAC), "ascii")

        container = Container(len_ubic=len_ubic,
                              ubicacion=ubicacion,
                              opciones=opciones,
                              len_opciones=len_opciones,
                              tachas=tachas,
                              len_tachas=len_tachas,
                              len_preferencias=len_preferencias,
                              preferencias=preferencias)
        built = struct_voto.build(container)
        return built
```

# Struct struct_voto
El el codigo de este struct no se puede ver de forma explicita un atributo que corresponde a fecha y hora de la creacion del voto

app/msa/core/documentos/structs.py
```python
struct_voto = Struct(
    "voto",
    Bytes("len_ubic", LEN_LEN_UBIC),
    Bytes("ubicacion", lambda ctx: int(ctx.len_ubic)),
    Bytes("len_opciones", LEN_LEN_OPC),
    Array(lambda ctx: int(ctx.len_opciones), UBInt16("opciones")),
    Bytes("len_tachas", LEN_LEN_OPC),
    Array(lambda ctx: int(ctx.len_tachas), UBInt16("tachas")),
    Bytes("len_preferencias", LEN_LEN_OPC),
    Array(lambda ctx: int(ctx.len_preferencias), UBInt16("preferencias"))
)
```


# IPC Service - Registrar Voto en un Tag
En esta clase se tiene metodo llamado "registrar", el cual tiene la funcion de grabar los datos de una "seleccion" codificada en base64 que es utilizada como parametro llamado "tag".
Se utilizan esos parametros para llamar un metodo de la misma instancia, el metodo "guardar_tag" agrega la variable "serial_number" al payload utilizado y encriptado con la funcion "encriptar_voto".
Luego se llama el metodo de la misma instancia llamado "write", donde se escriben los bytes en el chip RFID y luego procede a marcar los bloques del chip rfid como read only, se utilizada la variable "marcar_ro" y "success_quemado" para ejecutar las rutinas para transformar el chip rfid en modo solo lectura.
Los metodos "registrar", "guardar_tag", "write" no agregan ninguna variable o campo con los datos de la fecha y la hora de la creacion del voto en cuestion.

app/msa/core/ipc/server/armve_controller.py
```python
class ARMVEController(object):

    """Controlador para el ARMVEService."""

    def registrar(self, tag, solo_imprimir=False, aes_key=False, mesa=None, convertir=False):
        """Registra un voto. 

        Argumentos:
            tag -- el voto a registrar serializado como tag.
            solo_imprimir -- no guarda el tag, solo imprime.
            aes_key -- la clave con la que vamos a encriptar.
        """
        seleccion = Seleccion.desde_tag(tag, mesa, convertir)
        if seleccion is not None:
            # si la seleccion es válida guardamos el tag (en caso de que sea
            #  necesario)
            if solo_imprimir:
                tag_guardado = True
            else:
                tag_guardado = self.guardar_tag(TAG_VOTO, tag, marcar_ro,
                                                aes_key)


    def guardar_tag(self, tipo_tag, data, marcar_ro, aes_key=False):
        """Guarda un tag.

        Argumentos:
            tipo_tag -- el tipo de tag a guardar.
            data -- el contenido del tag a guardar.
            marcar_ro -- quema el tag.
        """
        try:
            # si el estado del papel tiene todas las condiciones requeridas
            # para guardar el tag.
            if self.parent.printer.is_paper_ready():
                # traigo los tags
                tags = self.parent.rfid.get_tags()
                # si tengo un solo tag y puedo guardar.
                if (tags is not None and tags[0] is not None and
                    tags[0]["number"] == 1):

                    serial_number = tags[0]["serial_number"][0]

                    # si es un voto y tengo la key de encriptacion lo encripto
                    if tipo_tag == TAG_VOTO and aes_key:
                        data = encriptar_voto(aes_key, serial_number, data)
                    # guardamos el tag y obtenemos el estado de grabación.
                    guardado = self.write(serial_number, tipo_tag, data,
                                          marcar_ro)

    def write(self, serial, tipo, data, marcar_ro):
        """Escribe un tag.

        Argumentos:
            serial -- el numero de serie del tag.
            tipo -- tipo de tag a guardar
            data -- datos que queremos guardar en el tag.
            marcar_ro -- un booleano que expresa si queremos quemar el tag.
        """
        success = False
        success_quemado = False
        rfid = self.parent.rfid
        # transformamos el tipo de tag en su version binaria
        tipo = TIPOS_TAGS_REV[tipo]
        # comprobamos que ningun sector del chip no esté quemado
        readonly = self._tag_readonly(serial)
        if not readonly:
            # traemos el header
            header_data = rfid.read_block(serial, 0)
            # nos aseguramos de que el tag esté presente y que no hubo ningún
            # error de lectura
            if header_data is not None and header_data[3] != MSG_ERROR:
                # vamos a intentar grabar el tag tres veces, sino asumimos que
                # no se puede grabar
                retries_left = 3
                while not success and retries_left:
                    # Grabo el tag
                    rfid.write_tag(serial, tipo, TOKEN, data)
                    # Chequeo la data a ver si se grabó bien. Si la data que
                    # quise grabar es diferente intento de nuevo
                    success = self._check_data(serial, data, tipo)
                    retries_left -= 1
                # si la grabacion fue un exito voy a quermarlo
                if success and marcar_ro:
                    retries_left = 3
                    first_block = 0
                    number = get_tag_n_blocks(serial)
                    success_write = success
                    while not success_quemado and retries_left:
                        # Quemo el tag
                        if first_block is not None:
                            respuesta_quemar_tag = rfid.set_read_only_blocks(serial, first_block, number)
                            logger.info("respuesta_quemar_tag es : %s", respuesta_quemar_tag)

                            # Tengo que esperar un poco porque es lo que tarda en responder el ARM
                            # tiempo en marcar bloques como RO slix2>slix1
                            # 0.6 * 3 (retries) ~= 1.8
                            #sleep(0.6)
                            # Chequeo que el quemado haya sido satisfactorio
                            quemado_info = self._check_quemado(serial)
                            logger.info(quemado_info)
                            success_quemado = quemado_info['success']
                            number = quemado_info['amount_not_ro']
                            first_block = quemado_info['first_block_not_ro']
                            success = success_write and success_quemado
                            logger.info("success_quemado es : %s", success_quemado)
                            logger.info("success es : %s", success)
                        retries_left -= 1
        return success

```

# Encriptar
Las funciones "encriptar" y "encriptar_voto" no agregan ninguna variable que represente la fecha y la hora de la creacion del voto en cuestion


app/msa/core/crypto/__init__.py

```python
def encriptar_voto(aes_key, serial_number, data):
    """Funcion de alto nivel para encriptar un voto.

    Argumentos:
        aes_key -- un stream de 16 bytes con la clave de encriptación.
        serial_number -- un stream de 8 bytes con el serial_number del tag.
        data --  el stream de bytes que queremos encriptar.
    """
    ret = data
    # si no queremos encriptar el voto devolvemos los datos que nos mandaron
    if ENCRIPTAR_VOTO:
        # El vector tiene que tener 12 bytes asi que le agregamos 4 bytes como
        # padding
        init_vector = serial_number + PADDING_SERIAL
        gcm_tag, data_encriptada = encriptar(aes_key, init_vector, data)
        # armamos un container de construct para armar el voto con el formato
        # correcto
        contenedor = Container(gcm_tag=gcm_tag, len_datos=len(data_encriptada),
                               datos=data_encriptada)
        ret = struct_voto.build(contenedor)

    return ret

def encriptar(aes_key, init_vector, input_, associated_data=None, tag_size=16):
    """Encripta un stream de bytes.

    Argumentos:
        aes_key -- un stream de 16 bytes con la clave de encriptación.
        init_vector -- un stream de 12 bytes con el vector de inicialización.
        input_ --  el stream de bytes que queremos encriptar.
        associated_data -- la data adicional que queremos usar para encriptar.
        tag_size -- tamaño de la etiqueta de autenticación (128 bits en gral.)
    """
    # Creamos el cifrador
    algorithm = AES(aes_key)
    op_mode = GCM(init_vector, min_tag_length=tag_size)
    cipher = Cipher(algorithm, op_mode, backend=Backend())
    # Obtenemos el encriptador.
    encryptor = cipher.encryptor()
    # Si existe agregamos los datos adicionales de autenticación.
    if associated_data is not None:
        encryptor.authenticate_additional_data(associated_data)
    # Encriptamos la informacion.
    encrypted = encryptor.update(input_) + encryptor.finalize()
    # Devolvemos en GCM tag y la data encriptada.
    return encryptor.tag[:tag_size], encrypted
```