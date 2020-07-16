all: test	
	go build dew.go

test:
	go test

clean:
	rm dew
