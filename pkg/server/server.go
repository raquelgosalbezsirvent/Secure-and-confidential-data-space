// El paquete server contiene el código del servidor.
// Interactúa con el cliente mediante una API JSON/HTTP
package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"sprout/pkg/api"
	"sprout/pkg/store"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

// server encapsula el estado de nuestro servidor
type server struct {
	db      store.Store // base de datos
	log     *log.Logger // logger para mensajes de error e información
	limiter *authLimiter
}

// Run inicia la base de datos y arranca el servidor HTTP.
func Run(masterKey []byte) error {
	if err := os.MkdirAll("data", 0755); err != nil {
		return fmt.Errorf("error creando la carpeta 'data': %w", err)
	}

	db, err := store.NewStore("bbolt", "data/server.db", masterKey)
	if err != nil {
		return fmt.Errorf("error abriendo base de datos: %v", err)
	}

	srv := &server{
		db:      db,
		log:     log.New(os.Stdout, "[srv] ", log.LstdFlags),
		limiter: newAuthLimiter(),
	}
	defer srv.db.Close()

	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	httpSrv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return httpSrv.ListenAndServeTLS("certs/server.pem", "certs/server.key")
}

// RGS
type passwordParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var argonParams = passwordParams{
	memory:      19 * 1024, // 19 MiB
	iterations:  2,
	parallelism: 1,
	saltLength:  16,
	keyLength:   32,
}

var (
	usernameRegex  = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,32}$`)
	errInvalidHash = errors.New("hash inválido")
)

type loginAttemptState struct {
	failedUntil time.Time
	fails       int
}

const (
	maxFailedAttempts = 5
	lockDuration      = 10 * time.Minute
)

type authLimiter struct {
	mu       sync.Mutex
	attempts map[string]loginAttemptState
}

type sessionData struct {
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

const sessionDuration = 1 * time.Hour

func newAuthLimiter() *authLimiter {
	return &authLimiter{
		attempts: make(map[string]loginAttemptState),
	}
}

func (l *authLimiter) isBlocked(username string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	st, ok := l.attempts[normalizeUsername(username)]
	if !ok {
		return false, 0
	}
	if time.Now().Before(st.failedUntil) {
		return true, time.Until(st.failedUntil)
	}
	return false, 0
}

func (l *authLimiter) recordFailure(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := normalizeUsername(username)
	st := l.attempts[key]
	st.fails++

	if st.fails >= maxFailedAttempts {
		st.failedUntil = time.Now().Add(lockDuration)
		st.fails = 0
	}
	l.attempts[key] = st
}

func (l *authLimiter) recordSuccess(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, normalizeUsername(username))
}

func normalizeUsername(username string) string {
	return strings.TrimSpace(strings.ToLower(username))
}

func validateUsername(username string) error {
	if !usernameRegex.MatchString(username) {
		return errors.New("nombre de usuario inválido")
	}
	return nil
}

func validatePassword(password string) error {
	if strings.TrimSpace(password) == "" {
		return errors.New("la contraseña no puede estar vacía")
	}
	if len([]byte(password)) < 8 {
		return errors.New("la contraseña debe tener al menos 8 caracteres")
	}
	if len([]byte(password)) > 128 {
		return errors.New("la contraseña es demasiado larga")
	}
	return nil
}

//RGS

// apiHandler decodifica la solicitud JSON, la despacha
// a la función correspondiente y devuelve la respuesta JSON.
func (s *server) apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Limitamos el tamaño del body para evitar sorpresas.
	// (No es una medida de seguridad "de verdad"; sólo robustez.)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB

	// Decodificamos la solicitud en una estructura api.Request
	var req api.Request
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}
	// Evitamos que se envíen múltiples objetos JSON concatenados.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}

	// Despacho según la acción solicitada
	var res api.Response
	switch req.Action {
	case api.ActionRegister:
		res = s.registerUser(req)
	case api.ActionLogin:
		res = s.loginUser(req)
	case api.ActionFetchData:
		res = s.fetchData(req)
	case api.ActionUpdateData:
		res = s.updateData(req)
	case api.ActionLogout:
		res = s.logoutUser(req)
	default:
		res = api.Response{Success: false, Message: "Acción desconocida"}
	}

	// Enviamos la respuesta en formato JSON
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// generateToken crea un token aleatorio criptográficamente seguro.
func (s *server) generateToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		s.log.Printf("Error generando token: %v", err)
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// registerUser registra un nuevo usuario, si no existe.
// - Guardamos la contraseña en el namespace 'auth'
// - Creamos entrada vacía en 'userdata' para el usuario
func (s *server) registerUser(req api.Request) api.Response {
	req.Username = normalizeUsername(req.Username)

	if err := validateUsername(req.Username); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	if err := validatePassword(req.Password); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	exists, err := s.userExists(req.Username)
	if err != nil {
		s.log.Printf("Comprobando existencia de usuario: %v", err)
		return api.Response{Success: false, Message: "Error interno del servidor"}
	}
	if exists {
		return api.Response{Success: false, Message: "El usuario ya existe"}
	}

	encodedHash, err := hashPasswordArgon2id(req.Password, argonParams)
	if err != nil {
		s.log.Printf("Generando hash Argon2id: %v", err)
		return api.Response{Success: false, Message: "Error interno del servidor"}
	}

	if err := s.db.Put("auth", []byte(req.Username), []byte(encodedHash)); err != nil {
		s.log.Printf("Guardando credenciales: %v", err)
		return api.Response{Success: false, Message: "Error interno del servidor"}
	}

	if err := s.db.Put("userdata", []byte(req.Username), []byte("")); err != nil {
		_ = s.db.Delete("auth", []byte(req.Username))
		s.log.Printf("Inicializando datos de usuario: %v", err)
		return api.Response{Success: false, Message: "Error interno del servidor"}
	}

	return api.Response{Success: true, Message: "Usuario registrado correctamente"}
}

// loginUser valida credenciales en el namespace 'auth' y genera un token en 'sessions'.
func (s *server) loginUser(req api.Request) api.Response {
	req.Username = normalizeUsername(req.Username)

	if blocked, _ := s.limiter.isBlocked(req.Username); blocked {
		return api.Response{
			Success: false,
			Message: "Demasiados intentos fallidos. Inténtalo más tarde.",
		}
	}

	if err := validateUsername(req.Username); err != nil {
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}
	if err := validatePassword(req.Password); err != nil {
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}

	storedHash, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		s.limiter.recordFailure(req.Username)
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}

	ok, needsRehash, err := verifyPasswordArgon2id(req.Password, string(storedHash))
	if err != nil {
		s.log.Printf("Verificando hash de %s: %v", req.Username, err)
		s.limiter.recordFailure(req.Username)
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}
	if !ok {
		s.limiter.recordFailure(req.Username)
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}

	s.limiter.recordSuccess(req.Username)

	if needsRehash {
		newHash, err := hashPasswordArgon2id(req.Password, argonParams)
		if err == nil {
			_ = s.db.Put("auth", []byte(req.Username), []byte(newHash))
		}
	}

	token := s.generateToken()
	if token == "" {
		return api.Response{Success: false, Message: "Error interno del servidor"}
	}

	now := time.Now().UTC()
	session := sessionData{
		Token:     token,
		CreatedAt: now,
		ExpiresAt: now.Add(sessionDuration),
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		s.log.Printf("Serializando sesión: %v", err)
		return api.Response{Success: false, Message: "Error interno del servidor"}
	}

	if err := s.db.Put("sessions", []byte(req.Username), sessionJSON); err != nil {
		s.log.Printf("Guardando sesión: %v", err)
		return api.Response{Success: false, Message: "Error interno del servidor"}
	}

	return api.Response{
		Success: true,
		Message: "Login exitoso",
		Token:   token,
	}
}

// fetchData verifica el token y retorna el contenido del namespace 'userdata'.
func (s *server) fetchData(req api.Request) api.Response {
	req.Username = normalizeUsername(req.Username)

	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	rawData, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener datos del usuario"}
	}

	return api.Response{
		Success: true,
		Message: "Datos privados de " + req.Username,
		Data:    string(rawData),
	}
}

// updateData cambia el contenido de 'userdata' (los "datos" del usuario)
// después de validar el token.
func (s *server) updateData(req api.Request) api.Response {
	req.Username = normalizeUsername(req.Username)

	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	if err := s.db.Put("userdata", []byte(req.Username), []byte(req.Data)); err != nil {
		return api.Response{Success: false, Message: "Error al actualizar datos del usuario"}
	}

	return api.Response{Success: true, Message: "Datos de usuario actualizados"}
}

// logoutUser borra la sesión
func (s *server) logoutUser(req api.Request) api.Response {
	req.Username = normalizeUsername(req.Username)

	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	if err := s.db.Delete("sessions", []byte(req.Username)); err != nil {
		return api.Response{Success: false, Message: "Error al cerrar sesión"}
	}

	return api.Response{Success: true, Message: "Sesión cerrada correctamente"}
}

// userExists comprueba si existe un usuario con la clave 'username'
// en 'auth'. Si no se encuentra, retorna false.
func (s *server) userExists(username string) (bool, error) {
	_, err := s.db.Get("auth", []byte(username))
	if err != nil {
		// Si no existe namespace o la clave, no es un error "real".
		if errors.Is(err, store.ErrNamespaceNotFound) || errors.Is(err, store.ErrKeyNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isTokenValid comprueba que el token almacenado en 'sessions'
// coincida con el token proporcionado.
func (s *server) isTokenValid(username, token string) bool {
	username = normalizeUsername(username)

	rawSession, err := s.db.Get("sessions", []byte(username))
	if err != nil {
		return false
	}

	var session sessionData
	if err := json.Unmarshal(rawSession, &session); err != nil {
		s.log.Printf("Sesión corrupta para %s: %v", username, err)
		_ = s.db.Delete("sessions", []byte(username))
		return false
	}

	if time.Now().UTC().After(session.ExpiresAt) {
		_ = s.db.Delete("sessions", []byte(username))
		return false
	}

	return subtle.ConstantTimeCompare([]byte(session.Token), []byte(token)) == 1
}

// RGS
func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func hashPasswordArgon2id(password string, p passwordParams) (string, error) {
	salt, err := generateRandomBytes(p.saltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		p.iterations,
		p.memory,
		p.parallelism,
		p.keyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.memory,
		p.iterations,
		p.parallelism,
		b64Salt,
		b64Hash,
	)

	return encoded, nil
}

func verifyPasswordArgon2id(password, encodedHash string) (bool, bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, false, errInvalidHash
	}

	if parts[1] != "argon2id" {
		return false, false, errInvalidHash
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil || version != argon2.Version {
		return false, false, errInvalidHash
	}

	params := passwordParams{}
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.iterations, &params.parallelism)
	if err != nil {
		return false, false, errInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, false, errInvalidHash
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, false, errInvalidHash
	}
	params.saltLength = uint32(len(salt))
	params.keyLength = uint32(len(hash))

	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		params.keyLength,
	)

	match := subtle.ConstantTimeCompare(hash, otherHash) == 1

	needsRehash := params.memory != argonParams.memory ||
		params.iterations != argonParams.iterations ||
		params.parallelism != argonParams.parallelism ||
		params.keyLength != argonParams.keyLength

	return match, needsRehash, nil
}

func LoadMasterKey() ([]byte, error) {
	metaBytes, err := os.ReadFile("secrets/db.key.meta")
	if err != nil {
		return nil, fmt.Errorf("leyendo metadata de clave maestra: %w", err)
	}

	encBytes, err := os.ReadFile("secrets/db.key.enc")
	if err != nil {
		return nil, fmt.Errorf("leyendo clave maestra cifrada: %w", err)
	}

	var meta masterKeyMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("parseando metadata de clave maestra: %w", err)
	}

	if meta.Version != 1 || meta.KDF != "argon2id" {
		return nil, errors.New("metadata de clave maestra no soportada")
	}

	salt, err := base64.StdEncoding.DecodeString(meta.Salt)
	if err != nil {
		return nil, fmt.Errorf("decodificando sal de clave maestra: %w", err)
	}

	password, err := promptMasterPassword()
	if err != nil {
		return nil, fmt.Errorf("obteniendo contraseña maestra: %w", err)
	}

	derivedKey := deriveKeyFromPassword(
		password,
		salt,
		meta.Memory,
		meta.Iterations,
		meta.Parallelism,
		meta.KeyLength,
	)

	var enc encryptedMasterKey
	if err := json.Unmarshal(encBytes, &enc); err != nil {
		return nil, fmt.Errorf("parseando clave maestra cifrada: %w", err)
	}

	if enc.Version != 1 || enc.Algorithm != "aes-256-gcm" {
		return nil, errors.New("formato de clave maestra cifrada no soportado")
	}

	nonce, err := base64.StdEncoding.DecodeString(enc.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decodificando nonce de clave maestra: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(enc.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decodificando ciphertext de clave maestra: %w", err)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("creando AES para clave maestra: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creando GCM para clave maestra: %w", err)
	}

	masterKey, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("contraseña maestra incorrecta o clave maestra corrupta")
	}

	if len(masterKey) != 32 {
		return nil, errors.New("clave maestra descifrada inválida")
	}

	return masterKey, nil
}

type encryptedMasterKey struct {
	Version    int    `json:"v"`
	Algorithm  string `json:"alg"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type masterKeyMeta struct {
	Version     int    `json:"v"`
	KDF         string `json:"kdf"`
	Salt        string `json:"salt"`
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	KeyLength   uint32 `json:"key_length"`
}

func deriveKeyFromPassword(password string, salt []byte, memory uint32, iterations uint32, parallelism uint8, keyLength uint32) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		keyLength,
	)
}

func promptMasterPassword() (string, error) {
	fmt.Print("Introduce la contraseña maestra del servidor: ")
	pwBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(pwBytes), nil
}

//RGS
