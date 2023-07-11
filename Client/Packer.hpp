// templates for packing arg array
#include <stdexcept>
extern int packingIndex;

template<typename T>
void packArgs(void** arr, unsigned int arrSize, T t)
{
	if (arrSize != 1) throw std::exception("Tried to pack too many arguments");
	arr[packingIndex] = t; // Always passed by address
	packingIndex = 0; //Reset for the next call
}

template<typename T, typename... Args>
void packArgs(void** arr, unsigned int arrSize, T t, Args... args) // recursive variadic function
{
	if (arrSize == 0) throw std::exception("Tried to pack too many arguments");
	arrSize--;
	arr[packingIndex] = t; // Always passed by address
	packingIndex++;
	packArgs(arr, arrSize, args...);
}