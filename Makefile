TARGET:=challenge
CFLAGS:=-no-pie -fstack-protector
TEST_SCRIPT:=./solution.py

.PHONY: all clean test

all: $(TARGET)
clean:
	rm $(TARGET)

$(TARGET): *.c
	$(CC) -o $@ $(CFLAGS) $<

test: $(TARGET)
	-$(TEST_SCRIPT) -b $(TARGET) | grep "FLAG{TEST_FLAG}" >/dev/null && echo "Test Success." || echo "Test Failed"
