all: build 
	@echo "build finished"


APP_NAME := sase-statistics

APP_DIR = .
#Wg part code 
all: build


build: 
	go build -o $(APP_NAME) $(APP_DIR)/main.go

clean: 
	rm $(APP_NAME)

# Install the binary file into system
ifeq ($(PREFIX),)
    PREFIX := /usr/bin
endif
install:
	install -m 755 $(APP_NAME) $(DESTDIR)$(PREFIX)
