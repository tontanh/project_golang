package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func DBinstance() *mongo.Client {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal(("Error loading .env file"))
	}
	MongoDb := os.Getenv("MONGODB_URL")
	// Set up a context with timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// MongoDB connection options.
	clientOptions := options.Client().ApplyURI(MongoDb)

	// Connect to MongoDB.
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}

	// Ping the database to check the connection.
	err = client.Ping(ctx, nil)
	if err != nil {
		_ = client.Disconnect(ctx) // Disconnect if the ping fails.
		log.Fatal("Failed to ping the database:", err)
	}

	fmt.Println("[INFO] : Connected to MongoDB! ")
	return client
}

var Client *mongo.Client = DBinstance()

func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	var collection *mongo.Collection = client.Database("golang000001").Collection(collectionName)
	return collection
}
