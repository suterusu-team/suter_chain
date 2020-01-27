pub trait PrimeGroup<T> {
    fn mul(x:T,y:T) -> T;
    fn pow(x:T,y:T) -> T;
}
