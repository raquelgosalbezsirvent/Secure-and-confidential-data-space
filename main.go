/*
'sprout' es una base para el desarrollo de prácticas en clase con Go.

Se puede compilar con "go build" en el directorio donde resida main.go
o "go build -o nombre" para que el ejecutable tenga un nombre distinto

curso: 			**rellenar**
asignatura: 	**antes de**
estudiantes: 	**entregar**
*/
package main

import (
	"log"
	"os"
	"time"

	"sprout/pkg/client"
	"sprout/pkg/server"
	"sprout/pkg/ui"
)

func main() {
	log := log.New(os.Stdout, "[main] ", log.LstdFlags)

	// RGS
	log.Println("Desbloqueando clave maestra...")
	masterKey, err := server.LoadMasterKey()
	if err != nil {
		log.Fatalf("Error cargando clave maestra: %v\n", err)
	}
	// RGS

	log.Println("Iniciando servidor...")
	go func() {
		if err := server.Run(masterKey); err != nil { // RGS
			log.Fatalf("Error del servidor: %v\n", err)
		}
	}()

	const totalSteps = 20
	for i := 1; i <= totalSteps; i++ {
		ui.PrintProgressBar(i, totalSteps, 30)
		time.Sleep(100 * time.Millisecond)
	}

	log.Println("Iniciando cliente...")
	client.Run()
}
