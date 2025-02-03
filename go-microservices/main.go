package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	details "github.com/Yashwin-2025/go-microservices/details"
	"github.com/gorilla/mux"
)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Checking application health")
	response := map[string]string{
		"status":    "UP",
		"timestamp": time.Now().String(),
	}
	json.NewEncoder(w).Encode(response) //to encode response into json and add it to the main response
}
func rootHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Serving the application homepage")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Application is up and running")
}
func detailsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Fetching the details")
	hostname, err := details.GetHostName()
	if err != nil {
		panic(err)
	}
	IP, _ := details.GetIP()
	fmt.Println(hostname, IP)
	response := map[string]string{
		"hostname":   hostname,
		"IP address": IP.String(),
	}
	json.NewEncoder(w).Encode(response) //to encode response into json and add it to the main response
}
func main() {
	r := mux.NewRouter()
	r.HandleFunc("/health", healthHandler)
	r.HandleFunc("/", rootHandler)
	r.HandleFunc("/details", detailsHandler)
	/*r.HandleFunc("/books/{title}/page/{page}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		title := vars["title"]
		page := vars["page"]

		fmt.Fprintf(w, "You've requested the book: %s on page %s\n", title, page)
	})*/
	log.Println("Server has started")
	log.Fatal(http.ListenAndServe(":80", r))
}

// func rootHandler(w http.ResponseWriter, r *http.Request) {
// 	fmt.Fprintf(w, "Hello, you've requested: %s with token : %s \n", r.URL.Path, r.URL.Query().Get("Token"))
// }

// func main() {
// 	http.HandleFunc("/", rootHandler)
// 	fs := http.FileServer(http.Dir("static/"))
// 	http.Handle("/static/", http.StripPrefix("/static/", fs))

// 	log.Println("The web server has started")
// 	http.ListenAndServe(":80", nil)
// }

// // package main

// // import (
// // 	"fmt"

// // 	geo "github.com/Yashwin-2025/go-microservices/geometry"

// // 	"rsc.io/quote"
// // )

// // // package to generate random quotes
// // func main() {
// // 	fmt.Println("Hello World")
// // 	fmt.Println(quote.Go())
// // 	fmt.Println(geo.Area(4.5, 3.6))
// // }
