package main

import (
	"github.com/StoveGI/stove-helper/pkg/config"
	"github.com/StoveGI/stove-helper/pkg/helper"
)

func main() {
	service, err := helper.NewService(config.LoadConfig())
	if err != nil {
		panic(err)
	}
	if err := service.Start(); err != nil {
		panic(err)
	}
}
