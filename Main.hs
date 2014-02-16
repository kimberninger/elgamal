-- |Main-Modul der Haskell-Implementation von ElGamal.
module Main where

import System.IO (putStr, putStrLn, hFlush, stdout, getLine)
import System.Random (getStdGen, newStdGen)
import ElGamal (encode, decode, generateKeys)

-- |Fragt über die Kommandozeile eine zu verschlüsselnde Nachricht als Folge von
-- Ziffern ab, verschlüsselt und entschlüsselt diese mit Hilfe des ElGamal-
-- Verfahrens und gibt zuletzt die benutzten Schlüssel sowie die ver- und
-- entschlüsselte Nachricht aus.
main :: IO ()
main = do
    putStr "zu verschlüsselnde Nachricht (m): "
    hFlush stdout
    gen <- getStdGen
    message <- fmap read getLine
    let (private@(p,a),public@(_,g,h)) = generateKeys gen
    gen' <- newStdGen
    let secret  = encode gen' public message
        decoded = decode private secret
    mapM_ putStrLn [ "Primzahl (p):                " ++ show p
                   , "privater Schlüssel (sk):     " ++ show a
                   , "öffentlicher Schlüssel (pk): " ++ show (g,h)
                   , "Chiffrat:                    " ++ show secret
                   , "entschlüsseltes Chiffrat:    " ++ show decoded]

