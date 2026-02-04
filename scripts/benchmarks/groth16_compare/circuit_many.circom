template MulAddMany() {
    signal input a;
    signal input b;
    signal input c;
    signal input d;
    signal input e;
    signal input f;
    signal input g;
    signal input h;
    signal output out;

    out <== a * b + c + d + e + f + g + h;
}

component main = MulAddMany();
