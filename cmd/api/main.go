package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"healthos/backend/internal/config"
	"healthos/backend/internal/server"
	"healthos/backend/internal/store"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration_error", "error", err)
		return 1
	}

	mongoStore, err := store.NewMongo(ctx, cfg.MongoURI, cfg.MongoDatabase)
	if err != nil {
		logger.Error("mongo_connection_error", "error", err)
		return 1
	}
	defer func() {
		if err := mongoStore.Close(context.Background()); err != nil {
			logger.Error("mongo_close_error", "error", err)
		}
	}()

	if err := mongoStore.EnsureIndexes(ctx); err != nil {
		logger.Error("mongo_index_error", "error", err)
		return 1
	}

	app, err := server.New(cfg, logger, mongoStore)
	if err != nil {
		logger.Error("server_init_error", "error", err)
		return 1
	}

	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           app.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("server_started", "addr", httpServer.Addr, "env", cfg.Env)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server_error", "error", err)
			serverErr <- err
			stop()
		}
	}()

	<-ctx.Done()
	select {
	case <-serverErr:
		return 1
	default:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("server_shutdown_error", "error", err)
		return 1
	}
	logger.Info("server_stopped")
	return 0
}
