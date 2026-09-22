CXX = g++
CXXFLAGS = -O2 -Wall -std=c++17
TARGET = analyzer

all: $(TARGET)

$(TARGET): analyzer.cpp
	$(CXX) $(CXXFLAGS) analyzer.cpp -o $(TARGET)

clean:
	rm -f $(TARGET) $(TARGET).exe
